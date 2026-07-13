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
    /// Bind address, port and remote port. Repeatable to forward several ports over
    /// ONE P2P session. Default: 127.0.0.1:1554:554
    #[arg(short, long, value_name = "[bind_address:]port:remote_port", action = clap::ArgAction::Append)]
    port: Vec<String>,
    /// Relay mode (experimental)
    #[arg(short, long)]
    relay: bool,
    /// Serial number of the camera
    serial: String,
}

type ChannelMap = Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>;
type ConnMap = Arc<Mutex<HashMap<u32, oneshot::Sender<bool>>>>;

/// Parse "[bind_address:]local_port:remote_port" into its parts.
fn parse_map(spec: &str) -> (String, u16, u16) {
    let parts: Vec<&str> = spec.split(':').collect();
    match parts.len() {
        2 => (
            "127.0.0.1".to_string(),
            parts[0].parse().expect("invalid local port"),
            parts[1].parse().expect("invalid remote port"),
        ),
        3 => (
            parts[0].to_string(),
            parts[1].parse().expect("invalid local port"),
            parts[2].parse().expect("invalid remote port"),
        ),
        _ => panic!("Invalid port specification: {}", spec),
    }
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    let serial = args.serial;
    let mut specs = args.port;
    if specs.is_empty() {
        specs.push("127.0.0.1:1554:554".to_string());
    }
    let maps: Vec<(String, u16, u16)> = specs.iter().map(|m| parse_map(m)).collect();

    // Bind every local listener up front (fail fast on a port collision).
    let mut listeners = Vec::new();
    for (bind_address, bind_port, remote_port) in &maps {
        let listener = TcpListener::bind(format!("{}:{}", bind_address, bind_port))
            .await
            .unwrap();
        listeners.push((listener, *remote_port));
    }

    let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let (socket, session) = p2p_handshake(socket, serial, args.relay).await;

    let (dh_tx, dh_rx) = mpsc::channel::<PTCPEvent>(128);
    let session = Arc::new(Mutex::new(session));

    let channels: ChannelMap = Arc::new(Mutex::new(HashMap::new()));
    let conn_channels: ConnMap = Arc::new(Mutex::new(HashMap::new()));

    println!("PTCP session established");

    let reader = Arc::new(socket);
    let writer = reader.clone();
    let session2 = session.clone();
    let channels_reader = channels.clone();
    let conn_reader = conn_channels.clone();

    // Heartbeat keeps the single P2P session alive for all listeners.
    let hb_tx = dh_tx.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            hb_tx.send(PTCPEvent::Heartbeat).await.unwrap();
        }
    });

    // One writer / one reader multiplex ALL listeners over the one session; the
    // per-connection remote port now travels inside PTCPEvent::Connect.
    tokio::spawn(async move {
        dh_writer(session, writer, dh_rx).await;
    });
    tokio::spawn(async move {
        dh_reader(session2, reader, channels_reader, conn_reader).await;
    });

    println!("Ready to connect!");
    for (bind_address, bind_port, remote_port) in &maps {
        println!("  {}:{}  ->  device:{}", bind_address, bind_port, remote_port);
    }

    // Spawn one accept loop per listener; each tags its connections with its own
    // remote port. The channel maps are keyed by the random realm id, so
    // connections from different listeners never collide.
    let mut handles = Vec::new();
    for (listener, remote_port) in listeners {
        let dh_tx = dh_tx.clone();
        let ch = channels.clone();
        let cc = conn_channels.clone();
        handles.push(tokio::spawn(accept_loop(listener, remote_port, dh_tx, ch, cc)));
    }
    for h in handles {
        let _ = h.await;
    }
}

/// Accept clients on one listener and bridge each to the device on `remote_port`.
async fn accept_loop(
    listener: TcpListener,
    remote_port: u16,
    dh_tx: mpsc::Sender<PTCPEvent>,
    channels: ChannelMap,
    conn_channels: ConnMap,
) {
    loop {
        let (client, addr) = listener.accept().await.unwrap();
        println!("Accepted connection from {} (-> device:{})", addr, remote_port);

        let (tx, rx) = mpsc::channel::<Vec<u8>>(128);
        let (conn_tx, conn_rx) = oneshot::channel::<bool>();
        let realm_id = rand::random::<u32>();

        channels.lock().unwrap().insert(realm_id, tx);
        conn_channels.lock().unwrap().insert(realm_id, conn_tx);

        let dh_tx2 = dh_tx.clone();
        dh_tx
            .send(PTCPEvent::Connect(realm_id, remote_port as u32))
            .await
            .unwrap();
        conn_rx.await.unwrap();

        let (reader, writer) = client.into_split();
        tokio::spawn(async move {
            process_reader(reader, realm_id, dh_tx2).await;
        });
        tokio::spawn(async move {
            process_writer(writer, rx).await;
        });
    }
}
