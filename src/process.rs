use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    sync::{mpsc, oneshot},
};

use crate::ptcp::{PTCPBody, PTCPEvent, PTCPPayload, PTCPSession, PTCP};

/**
 * Read data from the channel and write it back to the client
 */
pub async fn process_writer(
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    mut rx: mpsc::Receiver<Vec<u8>>,
) {
    loop {
        let data = rx.recv().await.unwrap();
        if writer.write_all(&data).await.is_err() {
            println!("Writer: Socket closed by peer.");
            break;
        }
    }
}

/**
 * Read data from the client and send it to the channel
 */
pub async fn process_reader(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    realm_id: u32,
    dh_tx: mpsc::Sender<PTCPEvent>,
) {
    let mut buf = [0u8; 4096];

    loop {
        let n = match reader.read(&mut buf).await {
            Ok(n) => {
                if n == 0 {
                    println!("Reader: Socket closed by peer.");
                    dh_tx.send(PTCPEvent::Disconnect(realm_id)).await.unwrap();
                    break;
                }

                n
            }
            Err(e) => {
                println!("Reader: {}", e);
                dh_tx.send(PTCPEvent::Disconnect(realm_id)).await.unwrap();
                break;
            }
        };

        dh_tx
            .send(PTCPEvent::Data(realm_id, buf[0..n].to_vec()))
            .await
            .unwrap();
    }
}

/**
* Read data from client and send it to devices
*/
pub async fn dh_writer(
    session: Arc<Mutex<PTCPSession>>,
    socket: Arc<UdpSocket>,
    mut dh_rx: mpsc::Receiver<PTCPEvent>,
    remote_port: u32,
) {
    loop {
        let ev = dh_rx.recv().await.unwrap();

        match ev {
            PTCPEvent::Heartbeat => {
                let p = session.lock().unwrap().send(PTCPBody::Heartbeat);
                socket.ptcp_request(p).await;
            }
            PTCPEvent::Connect(realm) => {
                let p = session.lock().unwrap().send(PTCPBody::Command(
                    [
                        b"\x11\x00\x00\x00".to_vec(),
                        realm.to_be_bytes().to_vec(),
                        b"\x00\x00\x00\x00".to_vec(),
                        remote_port.to_be_bytes().to_vec(),
                        b"\x7f\x00\x00\x01".to_vec(),
                    ]
                    .concat(),
                ));
                socket.ptcp_request(p).await;
            }
            PTCPEvent::Disconnect(realm) => {
                let p = session.lock().unwrap().send(PTCPBody::Command(
                    [
                        b"\x12\x00\x00\x00".to_vec(),
                        realm.to_be_bytes().to_vec(),
                        b"\x00\x00\x00\x00".to_vec(),
                        b"DISC".to_vec(),
                    ]
                    .concat(),
                ));
                socket.ptcp_request(p).await;
            }
            PTCPEvent::Data(realm, data) => {
                let p = session
                    .lock()
                    .unwrap()
                    .send(PTCPBody::Payload(PTCPPayload { realm, data }));
                socket.ptcp_request(p).await;
            }
        }
    }
}

/**
 * Read data from devices and send it to clients
 */
pub async fn dh_reader(
    session: Arc<Mutex<PTCPSession>>,
    socket: Arc<UdpSocket>,
    channels: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>,
    conn_channels: Arc<Mutex<HashMap<u32, oneshot::Sender<bool>>>>,
) {
    loop {
        let packet = socket.ptcp_read().await;
        let packet = session.lock().unwrap().recv(packet);

        if let PTCPBody::Empty = packet.body {
            continue;
        }

        let p = session.lock().unwrap().send(PTCPBody::Empty);
        socket.ptcp_request(p).await;

        match packet.body {
            PTCPBody::Command(c) => {
                if c[0] == 0x12 {
                    let realm = u32::from_be_bytes([c[4], c[5], c[6], c[7]]);
                    let status = String::from_utf8_lossy(&c[12..]).to_string();
                    println!("Realm {:08x} status: {}", realm, status);

                    if status == "CONN" {
                        conn_channels
                            .lock()
                            .unwrap()
                            .remove(&realm)
                            .unwrap()
                            .send(true)
                            .unwrap();
                    }
                }
            }
            PTCPBody::Payload(p) => {
                let tx = channels.lock().unwrap().get(&p.realm).unwrap().clone();

                if tx.send(p.data).await.is_err() {
                    println!("Realm {:08x} unavailable", p.realm);
                }
            }
            _ => {}
        }
    }
}
