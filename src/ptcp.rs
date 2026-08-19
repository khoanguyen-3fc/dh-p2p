use async_trait::async_trait;
use std::{
    cmp,
    collections::{HashSet, VecDeque},
    hash::{DefaultHasher, Hash, Hasher},
    io::ErrorKind,
};
use tokio::net::UdpSocket;

const RECENT_PACKET_WINDOW: usize = 1024;

fn sequence_is_after(candidate: u32, current: u32) -> bool {
    candidate != current && candidate.wrapping_sub(current) < (1 << 31)
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct PacketIdentity {
    sent: u32,
    recv: u32,
    pid: u32,
    lmid: u32,
    body_hash: u64,
}

pub enum PTCPEvent {
    Heartbeat,
    Connect(u32),
    Disconnect(u32),
    Data(u32, Vec<u8>),
}

pub struct PTCPPayload {
    pub realm: u32,
    pub data: Vec<u8>,
}

pub enum PTCPBody {
    Sync,
    Command(Vec<u8>),
    Payload(PTCPPayload),
    Bind(u32, u32),
    Status(u32, String),
    Heartbeat,
    Empty,
}

pub struct PTCPPacket {
    sent: u32,
    recv: u32,
    pid: u32,
    lmid: u32,
    rmid: u32,
    pub body: PTCPBody,
    duplicate: bool,
}

impl PTCPPayload {
    fn parse(data: &[u8]) -> PTCPPayload {
        assert!(data.len() >= 12, "Invalid payload");
        assert_eq!(data[0], 0x10, "Invalid header");

        // first 4 bytes it header
        let header = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let length = header & 0xFFFF;
        let realm = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let padding = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let data = data[12..].to_vec();

        assert_eq!(padding, 0, "Invalid padding");
        assert_eq!(length, data.len() as u32, "Invalid length");

        PTCPPayload { realm, data }
    }

    fn serialize(&self) -> Vec<u8> {
        let length = self.data.len() as u32;
        let header = 0x10000000 | length;
        let header = header.to_be_bytes();
        let realm = self.realm.to_be_bytes();
        let padding = 0u32.to_be_bytes();

        [
            header.to_vec(),
            realm.to_vec(),
            padding.to_vec(),
            self.data.clone(),
        ]
        .concat()
    }
}

impl std::fmt::Debug for PTCPPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "length: {}, realm: 0x{:08x}, data: [{}{}]",
            self.data.len(),
            self.realm,
            self.data[0..cmp::min(self.data.len(), 16)]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" "),
            if self.data.len() > 16 { " ..." } else { "" },
        )
    }
}

impl std::fmt::Debug for PTCPBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PTCPBody::Sync => write!(f, "Sync"),
            PTCPBody::Command(data) => write!(
                f,
                "Command([{}])",
                data.iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
            PTCPBody::Payload(payload) => write!(f, "{:?}", payload),
            PTCPBody::Bind(realm, port) => {
                write!(f, "Bind {{ realm: 0x{:08x}, port: {} }}", realm, port)
            }
            PTCPBody::Status(realm, status) => {
                write!(f, "Status {{ realm: 0x{:08x}, status: {} }}", realm, status)
            }
            PTCPBody::Heartbeat => write!(f, "Heartbeat"),
            PTCPBody::Empty => write!(f, "Empty"),
        }
    }
}

impl std::fmt::Debug for PTCPPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PTCPPacket {{ sent: {}, recv: {}, pid: 0x{:08x}, lmid: 0x{:08x}, rmid: 0x{:08x}, body: {:?} }}",
            self.sent, self.recv, self.pid, self.lmid, self.rmid, self.body
        )
    }
}

impl PTCPBody {
    fn parse(data: &[u8]) -> PTCPBody {
        if data.len() == 0 {
            return PTCPBody::Empty;
        }

        assert!(data.len() >= 4, "Invalid body");

        match data[0] {
            0x00 => PTCPBody::Sync,
            0x10 => PTCPBody::Payload(PTCPPayload::parse(data)),
            0x11 => PTCPBody::Bind(
                u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
                u32::from_be_bytes([data[12], data[13], data[14], data[15]]),
            ),
            0x12 => {
                let realm = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                let status = String::from_utf8_lossy(&data[12..]).to_string();
                PTCPBody::Status(realm, status)
            }
            0x13 => PTCPBody::Heartbeat,
            _ => PTCPBody::Command(data.to_vec()),
        }
    }

    fn serialize(&self) -> Vec<u8> {
        match self {
            PTCPBody::Sync => b"\x00\x03\x01\x00".to_vec(),
            PTCPBody::Command(data) => data.to_vec(),
            PTCPBody::Payload(payload) => payload.serialize(),
            PTCPBody::Bind(realm, port) => [
                b"\x11\x00\x00\x00".to_vec(),
                realm.to_be_bytes().to_vec(),
                b"\x00\x00\x00\x00".to_vec(),
                port.to_be_bytes().to_vec(),
                b"\x7f\x00\x00\x01".to_vec(),
            ]
            .concat(),
            PTCPBody::Status(realm, status) => [
                b"\x12\x00\x00\x00".to_vec(),
                realm.to_be_bytes().to_vec(),
                b"\x00\x00\x00\x00".to_vec(),
                status.as_bytes().to_vec(),
            ]
            .concat(),
            PTCPBody::Heartbeat => b"\x13\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
            PTCPBody::Empty => Vec::new(),
        }
    }

    fn len(&self) -> usize {
        match self {
            PTCPBody::Sync => 4,
            PTCPBody::Command(data) => data.len(),
            PTCPBody::Payload(payload) => payload.data.len() + 12,
            PTCPBody::Bind(_, _) => 20,
            PTCPBody::Status(_, status) => status.len() + 12,
            PTCPBody::Heartbeat => 12,
            PTCPBody::Empty => 0,
        }
    }
}

impl PTCPPacket {
    fn parse(data: &[u8]) -> PTCPPacket {
        assert!(data.len() >= 24, "Invalid packet");

        let magic = &data[0..4];

        assert_eq!(magic, b"PTCP", "Invalid magic");

        let sent = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let recv = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let pid = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let lmid = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        let rmid = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
        let body = PTCPBody::parse(&data[24..]);

        PTCPPacket {
            sent,
            recv,
            pid,
            lmid,
            rmid,
            body,
            duplicate: false,
        }
    }

    fn serialize(&self) -> Vec<u8> {
        [
            b"PTCP".to_vec(),
            self.sent.to_be_bytes().to_vec(),
            self.recv.to_be_bytes().to_vec(),
            self.pid.to_be_bytes().to_vec(),
            self.lmid.to_be_bytes().to_vec(),
            self.rmid.to_be_bytes().to_vec(),
            self.body.serialize(),
        ]
        .concat()
    }

    fn try_print_data(&self) {
        if let PTCPBody::Payload(p) = &self.body {
            if p.data.len() > 4 && p.data.iter().all(|b| *b < 0x80) {
                println!("{}", String::from_utf8_lossy(&p.data));
            }
        }
    }

    fn identity(&self) -> PacketIdentity {
        let mut hasher = DefaultHasher::new();
        self.body.serialize().hash(&mut hasher);

        PacketIdentity {
            sent: self.sent,
            recv: self.recv,
            pid: self.pid,
            lmid: self.lmid,
            body_hash: hasher.finish(),
        }
    }

    pub fn is_duplicate(&self) -> bool {
        self.duplicate
    }
}

pub struct PTCPSession {
    sent: u32,
    recv: u32,
    count: u32,
    id: u32,
    rmid: u32,
    recent_packets: HashSet<PacketIdentity>,
    recent_packet_order: VecDeque<PacketIdentity>,
}

impl PTCPSession {
    pub fn new() -> PTCPSession {
        PTCPSession {
            sent: 0,
            recv: 0,
            count: 0,
            id: 0,
            rmid: 0,
            recent_packets: HashSet::new(),
            recent_packet_order: VecDeque::new(),
        }
    }

    pub fn send(&mut self, body: PTCPBody) -> PTCPPacket {
        let sent = self.sent;
        let recv = self.recv;
        let pid = match body {
            PTCPBody::Sync => 0x0002FFFF,
            _ => 0x0000FFFF - self.count,
        };
        let lmid = self.id;
        let rmid = self.rmid;

        /*
         * Update counters
         */
        self.sent += body.len() as u32;

        self.id += 1;
        self.count += match body {
            PTCPBody::Sync => 0,
            PTCPBody::Empty => 0,
            _ => 1,
        };

        PTCPPacket {
            sent,
            recv,
            pid,
            lmid,
            rmid,
            body,
            duplicate: false,
        }
    }

    pub fn recv(&mut self, mut packet: PTCPPacket) -> PTCPPacket {
        let identity = packet.identity();

        if self.recent_packets.contains(&identity) {
            packet.duplicate = true;
            self.rmid = packet.lmid;
            return packet;
        }

        self.recent_packets.insert(identity);
        self.recent_packet_order.push_back(identity);
        if self.recent_packet_order.len() > RECENT_PACKET_WINDOW {
            if let Some(expired) = self.recent_packet_order.pop_front() {
                self.recent_packets.remove(&expired);
            }
        }

        // `sent` is the remote byte offset at the start of this body. Relay
        // servers retransmit Sync and payload datagrams without advancing it,
        // so summing every received body acknowledges bytes that were never
        // sent and eventually stalls the PTCP receive window.
        let remote_end = packet.sent.wrapping_add(packet.body.len() as u32);
        if sequence_is_after(remote_end, self.recv) {
            self.recv = remote_end;
        }
        self.rmid = packet.lmid;

        packet
    }
}

#[async_trait]
pub trait PTCP {
    async fn ptcp_request(&self, packet: PTCPPacket);
    async fn ptcp_read(&self) -> PTCPPacket;
}

#[async_trait]
impl PTCP for UdpSocket {
    async fn ptcp_request(&self, packet: PTCPPacket) {
        println!(">>> {}", self.peer_addr().unwrap());
        println!("{:?}", packet);
        packet.try_print_data();
        println!("---");

        let packet = packet.serialize();
        self.send(&packet).await.unwrap();
    }

    async fn ptcp_read(&self) -> PTCPPacket {
        println!("### {}", self.peer_addr().unwrap());

        let mut buf = [0u8; 4096];
        let n = loop {
            match self.recv(&mut buf).await {
                Ok(n) => break n,
                Err(e)
                    if matches!(
                        e.kind(),
                        ErrorKind::ConnectionRefused | ErrorKind::Interrupted
                    ) =>
                {
                    eprintln!("PTCP receive error ({e}); retrying");
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
                Err(e) => panic!("PTCP receive failed: {e}"),
            }
        };

        println!("<<< {}", self.peer_addr().unwrap());
        let packet = PTCPPacket::parse(&buf[0..n]);
        println!("{:?}", packet);
        packet.try_print_data();
        println!("---");

        packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(lmid: u32, body: PTCPBody) -> PTCPPacket {
        PTCPPacket {
            sent: 10,
            recv: 20,
            pid: 30,
            lmid,
            rmid: 40,
            body,
            duplicate: false,
        }
    }

    #[test]
    fn retransmitted_packet_is_counted_once() {
        let mut session = PTCPSession::new();

        let first = session.recv(packet(50, PTCPBody::Heartbeat));
        let duplicate = session.recv(packet(50, PTCPBody::Heartbeat));

        assert!(!first.is_duplicate());
        assert!(duplicate.is_duplicate());
        assert_eq!(session.recv, 22);
    }

    #[test]
    fn same_message_id_with_different_body_is_not_a_duplicate() {
        let mut session = PTCPSession::new();

        let empty = session.recv(packet(50, PTCPBody::Empty));
        let heartbeat = session.recv(packet(50, PTCPBody::Heartbeat));

        assert!(!empty.is_duplicate());
        assert!(!heartbeat.is_duplicate());
        assert_eq!(session.recv, 22);
    }

    #[test]
    fn receive_ack_uses_remote_offset_and_never_moves_backwards() {
        let mut session = PTCPSession::new();

        let mut later = packet(50, PTCPBody::Heartbeat);
        later.sent = 100;
        session.recv(later);

        let mut earlier = packet(51, PTCPBody::Heartbeat);
        earlier.sent = 50;
        session.recv(earlier);

        assert_eq!(session.recv, 112);
    }

    #[test]
    fn receive_ack_handles_sequence_wraparound() {
        let mut session = PTCPSession::new();
        session.recv = u32::MAX - 5;

        let mut wrapped = packet(50, PTCPBody::Heartbeat);
        wrapped.sent = u32::MAX - 3;
        session.recv(wrapped);

        assert_eq!(session.recv, 8);
    }
}
