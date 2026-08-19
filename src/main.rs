use clap::Parser;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::{mpsc, oneshot, Semaphore},
    time::{timeout, Duration},
};

use crate::{
    dh::p2p_handshake,
    process::{dh_reader, dh_writer, process_reader, process_writer},
    ptcp::PTCPEvent,
};

mod dh;
mod process;
mod ptcp;

#[derive(Parser)]
#[command(about = "A PoC implementation of TCP tunneling over Dahua P2P protocol.", long_about = None)]
struct Cli {
    /// Bind address, port and remote port. Default: 127.0.0.1:1554:554
    #[arg(short, long, value_name = "[bind_address:]port:remote_port")]
    port: Option<String>,
    /// Relay mode (experimental)
    #[arg(short, long)]
    relay: bool,
    /// Serial number of the camera
    serial: String,
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    let serial = args.serial;
    let port = args.port.unwrap_or("127.0.0.1:1554:554".to_string());

    let parts: Vec<&str> = port.split(':').collect();
    let (bind_address, bind_port, remote_port): (&str, u16, u16) = match parts.len() {
        2 => (
            "127.0.0.1",
            parts[0].parse().unwrap(),
            parts[1].parse().unwrap(),
        ),
        3 => (
            parts[0],
            parts[1].parse().unwrap(),
            parts[2].parse().unwrap(),
        ),
        _ => panic!("Invalid port specification"),
    };

    // Bind the listener to the address
    let listener = TcpListener::bind(format!("{}:{}", bind_address, bind_port))
        .await
        .unwrap();

    let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();

    let (socket, session) = p2p_handshake(socket, serial, args.relay).await;

    let (dh_tx, dh_rx) = mpsc::channel::<PTCPEvent>(128);
    let session = Arc::new(Mutex::new(session));

    let channels = Arc::new(Mutex::new(HashMap::<u32, mpsc::Sender<Vec<u8>>>::new()));
    let conn_channels = Arc::new(Mutex::new(HashMap::<u32, oneshot::Sender<bool>>::new()));
    let disconnect_channels = Arc::new(Mutex::new(HashMap::<u32, oneshot::Sender<()>>::new()));
    let realm_gate = Arc::new(Semaphore::new(1));

    println!("PTCP session established");

    /*
     * Clone the handles
     */

    let reader = Arc::new(socket);
    let writer = reader.clone();

    let session2 = session.clone();
    let channels2 = channels.clone();
    let conn_channels2 = conn_channels.clone();
    let disconnect_channels2 = disconnect_channels.clone();
    let writer_channels = channels.clone();
    let writer_conn_channels = conn_channels.clone();

    let hb_tx = dh_tx.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            if hb_tx.send(PTCPEvent::Heartbeat).await.is_err() {
                break;
            }
        }
    });

    tokio::spawn(async move {
        dh_writer(
            session,
            writer,
            dh_rx,
            remote_port.into(),
            writer_channels,
            writer_conn_channels,
        )
        .await;
    });

    tokio::spawn(async move {
        dh_reader(
            session2,
            reader,
            channels,
            conn_channels,
            disconnect_channels,
        )
        .await;
    });

    println!("Ready to connect!");
    if remote_port == 554 {
        println!(
            "RTSP URL: rtsp://127.0.0.1{}/cam/realmonitor?channel=1&subtype=0",
            if bind_port != 554 {
                format!(":{}", bind_port)
            } else {
                String::new()
            }
        );
    }

    loop {
        // The second item contains the IP and port of the new connection.
        let (client, addr) = listener.accept().await.unwrap();
        println!("Accepted connection from {}", addr);

        // Dahua closes each bound realm independently. Do not bind the next
        // client until the previous realm has acknowledged its disconnect.
        let realm_permit = realm_gate.clone().acquire_owned().await.unwrap();

        // Create a channel for the client
        let (tx, rx) = mpsc::channel::<Vec<u8>>(128);
        let (conn_tx, mut conn_rx) = oneshot::channel::<bool>();
        let (disconnect_tx, disconnect_rx) = oneshot::channel::<()>();
        let dh_tx = dh_tx.clone();

        let realm_id = rand::random::<u32>();

        // Store the channel in the map
        channels2.lock().unwrap().insert(realm_id, tx);
        conn_channels2.lock().unwrap().insert(realm_id, conn_tx);
        disconnect_channels2
            .lock()
            .unwrap()
            .insert(realm_id, disconnect_tx);

        let mut connected = false;
        for attempt in 1..=3 {
            if dh_tx.send(PTCPEvent::Connect(realm_id)).await.is_err() {
                channels2.lock().unwrap().remove(&realm_id);
                conn_channels2.lock().unwrap().remove(&realm_id);
                disconnect_channels2.lock().unwrap().remove(&realm_id);
                return;
            }

            match timeout(Duration::from_secs(5), &mut conn_rx).await {
                Ok(Ok(true)) => {
                    connected = true;
                    break;
                }
                Ok(_) => break,
                Err(_) if attempt < 3 => {
                    eprintln!(
                        "Retrying bind for realm {:08x} ({}/3)",
                        realm_id,
                        attempt + 1
                    );
                }
                Err(_) => {}
            }
        }

        if !connected {
            eprintln!("Timed out binding realm {:08x}", realm_id);
            channels2.lock().unwrap().remove(&realm_id);
            conn_channels2.lock().unwrap().remove(&realm_id);
            disconnect_channels2.lock().unwrap().remove(&realm_id);
            let _ = dh_tx.send(PTCPEvent::Disconnect(realm_id)).await;
            continue;
        }

        let (reader, writer) = client.into_split();

        let realm_disconnect_channels = disconnect_channels2.clone();
        tokio::spawn(async move {
            process_reader(reader, realm_id, dh_tx).await;

            if timeout(Duration::from_secs(2), disconnect_rx)
                .await
                .is_err()
            {
                realm_disconnect_channels.lock().unwrap().remove(&realm_id);
                eprintln!("Timed out disconnecting realm {:08x}", realm_id);
            }

            drop(realm_permit);
        });

        tokio::spawn(async move {
            process_writer(writer, rx).await;
        });
    }
}
