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
    /// Bind address, port and remote port. Repeat for multiple mappings.
    #[arg(short, long, value_name = "[bind_address:]port:remote_port")]
    port: Vec<String>,
    /// Relay mode (experimental)
    #[arg(short, long)]
    relay: bool,
    /// Serial number of the camera
    serial: String,
}

#[derive(Debug, Eq, PartialEq)]
struct PortMapping {
    bind_address: String,
    bind_port: u16,
    remote_port: u16,
}

fn parse_port_mapping(port: &str) -> PortMapping {
    let parts: Vec<&str> = port.split(':').collect();
    let (bind_address, bind_port, remote_port) = match parts.as_slice() {
        [bind_port, remote_port] => ("127.0.0.1", bind_port, remote_port),
        [bind_address, bind_port, remote_port] => (*bind_address, bind_port, remote_port),
        _ => panic!("Invalid port specification"),
    };

    PortMapping {
        bind_address: bind_address.to_string(),
        bind_port: bind_port.parse().unwrap(),
        remote_port: remote_port.parse().unwrap(),
    }
}

async fn serve_listener(
    listener: TcpListener,
    remote_port: u32,
    dh_tx: mpsc::Sender<PTCPEvent>,
    channels: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>,
    conn_channels: Arc<Mutex<HashMap<u32, oneshot::Sender<bool>>>>,
    disconnect_channels: Arc<Mutex<HashMap<u32, oneshot::Sender<()>>>>,
    realm_gate: Arc<Semaphore>,
) {
    loop {
        let (client, addr) = listener.accept().await.unwrap();
        println!(
            "Accepted connection from {} for remote port {}",
            addr, remote_port
        );

        // Dahua closes each bound realm independently. Do not bind the next
        // client until the previous realm has acknowledged its disconnect.
        let realm_permit = realm_gate.clone().acquire_owned().await.unwrap();

        let (tx, rx) = mpsc::channel::<Vec<u8>>(128);
        let (conn_tx, mut conn_rx) = oneshot::channel::<bool>();
        let (disconnect_tx, disconnect_rx) = oneshot::channel::<()>();
        let realm_id = rand::random::<u32>();

        channels.lock().unwrap().insert(realm_id, tx);
        conn_channels.lock().unwrap().insert(realm_id, conn_tx);
        disconnect_channels
            .lock()
            .unwrap()
            .insert(realm_id, disconnect_tx);

        let mut connected = false;
        for attempt in 1..=3 {
            if dh_tx
                .send(PTCPEvent::Connect(realm_id, remote_port))
                .await
                .is_err()
            {
                channels.lock().unwrap().remove(&realm_id);
                conn_channels.lock().unwrap().remove(&realm_id);
                disconnect_channels.lock().unwrap().remove(&realm_id);
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
            channels.lock().unwrap().remove(&realm_id);
            conn_channels.lock().unwrap().remove(&realm_id);
            disconnect_channels.lock().unwrap().remove(&realm_id);
            let _ = dh_tx.send(PTCPEvent::Disconnect(realm_id)).await;
            continue;
        }

        let (reader, writer) = client.into_split();

        let realm_disconnect_channels = disconnect_channels.clone();
        let realm_dh_tx = dh_tx.clone();
        tokio::spawn(async move {
            process_reader(reader, realm_id, realm_dh_tx).await;

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

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    let serial = args.serial;
    let port_specs = if args.port.is_empty() {
        vec!["127.0.0.1:1554:554".to_string()]
    } else {
        args.port
    };

    let mut listeners = Vec::new();
    for port_spec in port_specs {
        let mapping = parse_port_mapping(&port_spec);
        let listener = TcpListener::bind(format!("{}:{}", mapping.bind_address, mapping.bind_port))
            .await
            .unwrap();
        listeners.push((listener, mapping));
    }

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
    for (listener, mapping) in listeners {
        if mapping.remote_port == 554 {
            println!(
                "RTSP URL: rtsp://127.0.0.1{}/cam/realmonitor?channel=1&subtype=0",
                if mapping.bind_port != 554 {
                    format!(":{}", mapping.bind_port)
                } else {
                    String::new()
                }
            );
        }

        let listener_dh_tx = dh_tx.clone();
        let listener_channels = channels2.clone();
        let listener_conn_channels = conn_channels2.clone();
        let listener_disconnect_channels = disconnect_channels2.clone();
        let listener_realm_gate = realm_gate.clone();
        tokio::spawn(async move {
            serve_listener(
                listener,
                mapping.remote_port.into(),
                listener_dh_tx,
                listener_channels,
                listener_conn_channels,
                listener_disconnect_channels,
                listener_realm_gate,
            )
            .await;
        });
    }

    std::future::pending::<()>().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default_bind_address_mapping() {
        assert_eq!(
            parse_port_mapping("1554:554"),
            PortMapping {
                bind_address: "127.0.0.1".to_string(),
                bind_port: 1554,
                remote_port: 554,
            }
        );
    }

    #[test]
    fn parses_explicit_bind_address_mapping() {
        assert_eq!(
            parse_port_mapping("0.0.0.0:8080:80"),
            PortMapping {
                bind_address: "0.0.0.0".to_string(),
                bind_port: 8080,
                remote_port: 80,
            }
        );
    }
}
