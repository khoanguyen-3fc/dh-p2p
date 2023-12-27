use clap::Parser;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::{mpsc, oneshot},
};

use crate::{
    dh::{p2p_handshake, p2p_handshake_relay},
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

    let (dh_tx, dh_rx) = mpsc::channel::<PTCPEvent>(128);
    let session = Arc::new(Mutex::new(if args.relay {
        p2p_handshake_relay(&socket, serial).await
    } else {
        p2p_handshake(&socket, serial).await
    }));

    let channels = Arc::new(Mutex::new(HashMap::<u32, mpsc::Sender<Vec<u8>>>::new()));
    let conn_channels = Arc::new(Mutex::new(HashMap::<u32, oneshot::Sender<bool>>::new()));

    println!("PTCP session established");

    /*
     * Clone the handles
     */

    let reader = Arc::new(socket);
    let writer = reader.clone();

    let session2 = session.clone();
    let channels2 = channels.clone();
    let conn_channels2 = conn_channels.clone();

    // TODO: implement duplex keepalive
    tokio::spawn(async move {
        dh_writer(session, writer, dh_rx, remote_port.into()).await;
    });

    tokio::spawn(async move {
        dh_reader(session2, reader, channels, conn_channels).await;
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

        // Create a channel for the client
        let (tx, rx) = mpsc::channel::<Vec<u8>>(128);
        let (conn_tx, conn_rx) = oneshot::channel::<bool>();
        let dh_tx = dh_tx.clone();

        let realm_id = rand::random::<u32>();

        // Store the channel in the map
        channels2.lock().unwrap().insert(realm_id, tx);
        conn_channels2.lock().unwrap().insert(realm_id, conn_tx);

        dh_tx.send(PTCPEvent::Connect(realm_id)).await.unwrap();
        conn_rx.await.unwrap();

        let (reader, writer) = client.into_split();

        tokio::spawn(async move {
            process_reader(reader, realm_id, dh_tx).await;
        });

        tokio::spawn(async move {
            process_writer(writer, rx).await;
        });
    }
}
