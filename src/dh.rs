use async_trait::async_trait;
use base64::Engine;
use sha1::Digest;
use std::collections::HashMap;
use tokio::net::UdpSocket;
use xml::reader::{EventReader, XmlEvent};

use crate::ptcp::{PTCPBody, PTCPSession, PTCP};

static MAIN_SERVER: &str = "www.easy4ipcloud.com:8800";

static USERNAME: &str = "P2PClient";
static USERKEY: &str = "YXQ3Mahe-5H-R1Z_";

static mut CSEQ: u32 = 0;

pub async fn p2p_handshake(socket: &UdpSocket, serial: String) -> PTCPSession {
    socket.connect(MAIN_SERVER).await.unwrap();

    socket.dh_request("/probe/p2psrv", None).await;
    socket.dh_read().await;

    socket
        .dh_request(format!("/online/p2psrv/{}", serial).as_ref(), None)
        .await;
    let p2psrv = &socket.dh_read().await.body.unwrap()["body/US"];

    socket.dh_request("/online/relay", None).await;
    let relay = &socket.dh_read().await.body.unwrap()["body/Address"];

    let socket2 = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    socket2.connect(p2psrv).await.unwrap();

    socket2
        .dh_request(format!("/probe/device/{}", serial).as_ref(), None)
        .await;
    socket2.dh_read().await;

    socket
        .dh_request(
            format!("/device/{}/p2p-channel", serial).as_ref(),
            Some(format!(
                "<body><Identify>d4 9e 67 a8 2b d4 7e 1e</Identify><IpEncrpt>true</IpEncrpt><LocalAddr>63.87.143.254,63.87.254.173:{}</LocalAddr><version>5.0.0</version></body>",
                socket.local_addr().unwrap().port(),
            ).as_ref()),
        )
        .await;

    socket2.connect(relay).await.unwrap();

    socket2.dh_request("/relay/agent", None).await;
    let data = socket2.dh_read().await.body.unwrap();
    let token = &data["body/Token"];
    let agent = &data["body/Agent"];

    socket2.connect(agent).await.unwrap();

    socket2
        .dh_request(
            format!("/relay/start/{}", token).as_ref(),
            Some("<body><Client>:0</Client></body>"),
        )
        .await;
    socket2.dh_read().await;

    let mut res = socket.dh_read().await;

    if res.code == 100 {
        res = socket.dh_read().await;
    }

    let device = &res.body.unwrap()["body/PubAddr"];

    socket.connect(device).await.unwrap();

    socket2.connect(MAIN_SERVER).await.unwrap();

    socket2
        .dh_request(
            format!("/device/{}/relay-channel", serial).as_ref(),
            Some(format!("<body><agentAddr>{}</agentAddr></body>", agent).as_ref()),
        )
        .await;

    socket2.connect(agent).await.unwrap();
    // TODO: check timeout
    socket2.dh_read().await;

    let mut session = PTCPSession::new();

    socket2
        .ptcp_request(session.send(PTCPBody::Command(b"\x00\x03\x01\x00".to_vec())))
        .await;
    session.recv(socket2.ptcp_read().await);

    socket2
        .ptcp_request(session.send(PTCPBody::Command(
            b"\x17\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
        )))
        .await;
    let mut res = session.recv(socket2.ptcp_read().await);

    while let PTCPBody::Empty = res.body {
        res = session.recv(socket2.ptcp_read().await);
    }

    let sign = match res.body {
        PTCPBody::Command(ref c) => &c[12..],
        _ => panic!("Invalid response"),
    };

    println!(
        "Sign: {}",
        sign.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join("")
    );

    println!(">>> {}", socket.peer_addr().unwrap());
    let data = b"\xff\xfe\xff\xe7\xde\xed\x5b\xbd\xb3\x03\xef\x13\x41\x2b\x12\xae\xf9\xba\xb2\x66\x7f\xd5\xff\xf7\x2b\x61\x98\x57\xd4\x2b\x81\xe1\xff\xfb\xff\xf7\xff\xfe\xa8\x13\x21\x02\xd2\x65";
    println!(
        "Raw [{}]",
        data.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ")
    );
    socket.send(data).await.unwrap();
    println!("---");

    println!("<<< {}", socket.peer_addr().unwrap());
    let mut buf = [0u8; 4096];
    let n = socket.recv(&mut buf).await.unwrap();
    println!(
        "Raw [{}]",
        buf[0..n]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ")
    );
    println!("---");

    println!(">>> {}", socket.peer_addr().unwrap());
    let data = b"\xfe\xfe\xff\xe7\xde\xed\x5b\xbd\xd3\xfa\x95\xab\x92\x98\xc8\xe0\x6b\x6e\x84\x4e\x7f\xd6\xff\xf7\x2b\x61\x98\x57\xd4\x2b\x81\xe1\xff\xfb\xff\xf7\xff\xfe\xa8\x13\x3f\x57\xfe\x37";
    println!(
        "Raw [{}]",
        data.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ")
    );
    socket.send(data).await.unwrap();
    println!("---");

    // read 5 times
    for _ in 0..5 {
        println!("<<< {}", socket.peer_addr().unwrap());
        let n = socket.recv(&mut buf).await.unwrap();
        println!(
            "Raw [{}]",
            buf[0..n]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ")
        );
        println!("---");
    }

    let mut session = PTCPSession::new();

    socket
        .ptcp_request(session.send(PTCPBody::Command(b"\x00\x03\x01\x00".to_vec())))
        .await;
    let mut res = session.recv(socket.ptcp_read().await);
    match res.body {
        PTCPBody::Command(ref c) => {
            assert_eq!(c, b"\x00\x03\x01\x00", "Invalid response");
        }
        _ => panic!("Invalid response"),
    }

    socket
        .ptcp_request(
            session.send(PTCPBody::Command(
                [
                    b"\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
                    sign.to_vec(),
                ]
                .concat(),
            )),
        )
        .await;

    res = session.recv(socket.ptcp_read().await);
    while let PTCPBody::Empty = res.body {
        res = session.recv(socket.ptcp_read().await);
    }
    match res.body {
        PTCPBody::Command(ref c) => {
            assert_eq!(c[0], 0x1A, "Invalid response");
        }
        _ => panic!("Invalid response"),
    }

    socket
        .ptcp_request(session.send(PTCPBody::Command(
            b"\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
        )))
        .await;
    res = session.recv(socket.ptcp_read().await);

    assert!(matches!(res.body, PTCPBody::Empty), "Invalid response");

    session
}

#[derive(Debug)]
#[allow(dead_code)]
struct DHResponse {
    version: String,
    code: u16,
    status: String,
    headers: HashMap<String, String>,
    body: Option<HashMap<String, String>>,
}

impl DHResponse {
    fn parse_body(body: &str) -> HashMap<String, String> {
        // XmlBody::Value("")
        let mut parser = EventReader::from_str(body);
        let mut stack = Vec::new();
        let mut tree = HashMap::new();

        loop {
            match parser.next() {
                Ok(XmlEvent::StartElement { name, .. }) => {
                    stack.push(name.local_name);
                }
                Ok(XmlEvent::EndElement { .. }) => {
                    stack.pop().unwrap();
                }
                Ok(XmlEvent::Characters(s)) => {
                    let key = stack.as_slice().join("/");
                    tree.insert(key, s);
                }
                Ok(XmlEvent::EndDocument) => {
                    break;
                }
                Err(e) => panic!("Error: {}", e),
                _ => {}
            }
        }

        tree
    }

    fn parse_response(res: &str) -> DHResponse {
        // split head and body by "\r\n\r\n"
        let mut parts = res.split("\r\n\r\n");
        let head = parts.next().unwrap();
        let body = parts.next().unwrap();

        let mut head_parts = head.split("\r\n");
        let mut status_line = head_parts.next().unwrap().split(" ");
        let version = status_line.next().unwrap().to_string();
        let code = status_line.next().unwrap().parse::<u16>().unwrap();
        let status = status_line.next().unwrap().to_string();

        let mut headers = HashMap::new();
        for line in head_parts {
            let mut parts = line.split(": ");
            let key = parts.next().unwrap().to_string();
            let value = parts.next().unwrap().to_string();
            headers.insert(key, value);
        }

        let body = match body.trim().len() {
            0 => None,
            _ => Some(DHResponse::parse_body(body)),
        };

        DHResponse {
            version,
            code,
            status,
            headers,
            body,
        }
    }
}

#[async_trait]
trait DHP2P {
    async fn dh_request(&self, path: &str, body: Option<&str>);
    async fn dh_read(&self) -> DHResponse;
}

#[async_trait]
impl DHP2P for UdpSocket {
    async fn dh_request(&self, path: &str, body: Option<&str>) {
        println!(">>> {}", self.peer_addr().unwrap());

        let method = match body {
            Some(_) => "DHPOST",
            None => "DHGET",
        };

        let body = match body {
            Some(s) => s,
            None => "",
        };

        // random a 32-bit number
        let nonce = rand::random::<u32>();
        // iso8601 time string
        let currdate = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let pwd = format!("{}{}DHP2P:{}:{}", nonce, currdate, USERNAME, USERKEY);

        // sha1 then base64
        let mut hasher = sha1::Sha1::new();
        hasher.update(pwd);
        let hash_digest = hasher.finalize();
        let digest = base64::engine::general_purpose::STANDARD.encode(&hash_digest);

        let seq: u32;
        unsafe {
            CSEQ += 1;
            seq = CSEQ;
        }

        let req = format!(
        "\
        {} {} HTTP/1.1\r\n\
        CSeq: {}\r\n\
        Authorization: WSSE profile=\"UsernameToken\"\r\n\
        X-WSSE: UsernameToken Username=\"{}\", PasswordDigest=\"{}\", Nonce=\"{}\", Created=\"{}\"\r\n\r\n{}",
        method, path, seq, USERNAME, digest, nonce, currdate, body,
    );

        println!("{}", req);
        self.send(req.as_bytes()).await.unwrap();
        println!("---");
    }

    async fn dh_read(&self) -> DHResponse {
        println!("<<< {}", self.peer_addr().unwrap());

        let mut buf = [0u8; 4096];
        let n = self.recv(&mut buf).await.unwrap();
        let res = String::from_utf8_lossy(&buf[0..n]);
        println!("{}", res);
        println!("---");

        let res = DHResponse::parse_response(&res);
        println!("{:?}", res);

        assert!(res.code < 300, "Error response: {}", res.status);

        res
    }
}