# RTSP Streaming with Dahua P2P Protocol Implementation

This is a proof of concept implementation of RTSP over Dahua P2P protocol. It works with Dahua and derived cameras / NVRs.

## Motivation

The Dahua P2P protocol is utilized for remote access to Dahua devices. It is commonly used by Dahua apps such as [gDMSS Lite](https://play.google.com/store/apps/details?id=com.mm.android.direct.gdmssphoneLite) on Android or [SmartPSS](https://dahuawiki.com/SmartPSS), [KBiVMS](https://kbvisiongroup.com/support/download-center.html) on Windows.

In my specific scenario, I have a KBVision CCTV system. Although I can access the cameras using the KBiVMS client, I primarily use non-Windows platforms. Therefore, I wanted to explore alternative options for streaming the video using an RTSP client, which is more widely supported. As a result, I decided to experiment with reimplementing the Dahua P2P protocol.

## Files

- Rust implementation:
  - `src/*.rs` - Rust source files
  - `Cargo.toml` - Rust dependencies
- Python implementation:
  - `main.py` - Main script
  - `helpers.py` - Helper functions
  - `requirements.txt` - Python dependencies
- Others:
  - `dh-p2p.lua` - Wireshark dissector for Dahua P2P protocol

## Rust implementation

Rust implementation utilizing async programming and message passing pattern, making it more efficient and flexible.

### Rust usage

```text
A PoC implementation of TCP tunneling over Dahua P2P protocol.

Usage: dh-p2p [OPTIONS] <SERIAL>

Arguments:
  <SERIAL>  Serial number of the camera

Options:
  -p, --port <[bind_address:]port:remote_port>
          Bind address, port and remote port. Repeat for multiple mappings
  -h, --help
          Print help
```

When `--port` is omitted, the default mapping is `127.0.0.1:1554:554`.
Multiple device ports can share one P2P session by repeating the option:

```bash
dh-p2p --port 127.0.0.1:18080:80 --port 127.0.0.1:1554:554 [CAMERA_SERIAL]
```

## Python implementation

The Python implementation of DH-P2P is a simple and straightforward approach. It is used for drafting and testing purposes due to its quick and easy-to-write nature. Additionally, the implementation is more linear and follows a top-down execution flow, making it easier to understand. Python, being a popular programming language, further contributes to its accessibility and familiarity among developers.

### Setup

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run
python main.py [CAMERA_SERIAL]

# Stream (e.g. with ffplay) rtsp://[username]:[password]@127.0.0.1/cam/realmonitor?channel=1&subtype=0
ffplay -rtsp_transport tcp -i "rtsp://[username]:[password]@127.0.0.1/cam/realmonitor?channel=1&subtype=0"
```

### Python usage

To use the script with a device that requires authentication when creating a channel, use the `-t 1` option.

When running in `--debug` mode or when the `--type` > 0, the `USERNAME` and `PASSWORD` arguments are mandatory. Additionally, make sure that `ffplay` is in the system path when debug mode is enabled.

A device is reachable only through the cloud it registered with. Dahua and derived devices use
easy4ip, the default; Amcrest devices use their own cloud, selected with `-c amcrest`:

```bash
python main.py -c amcrest [CAMERA_SERIAL]
```

```text
usage: main.py [-h] [-d] [-t TYPE] [-u USERNAME] [-p PASSWORD] [-c {amcrest,easy4ip}] serial

positional arguments:
  serial                Serial number of the camera

options:
  -h, --help            show this help message and exit
  -d, --debug           Enable debug mode
  -t TYPE, --type TYPE  Type of the camera
  -u USERNAME, --username USERNAME
                        Username of the camera
  -p PASSWORD, --password PASSWORD
                        Password of the camera
  -c {amcrest,easy4ip}, --cloud {amcrest,easy4ip}
                        P2P cloud the camera is registered with (default: easy4ip)
```

### Limitations

- Single threaded, so only one client can connect at a time
- Polling based, so it's inefficient and inflexible
- Not fully implemented (e.g. only simplex keep-alive, no mulpile connections, etc.)
- Work better with `ffplay` and `-rtsp_transport tcp` option
- Still unstable, can crash at any time

## Protocol description

For reverse engineering the protocol, I used [Wireshark](https://www.wireshark.org/) and [KBiVMS V2.02.0](https://kbvisiongroup.com/support/download-center.html) as a client on Windows. Using `dh-p2p.lua` dissector, you can see the protocol in Wireshark easier.

For RTSP client, either [VLC](https://www.videolan.org/vlc/) or [ffplay](https://ffmpeg.org/ffplay.html) can be used for easier control of the signals.

### Overview

```mermaid
graph LR
  App[[This script]]
  Service[Easy4IPCloud]
  Device[Camera/NVR]
  App -- 1 --> Service
  Service -- 2 --> Device
  App <-. 3 .-> Device
```

The Dahua P2P protocol initiates with a P2P handshake. This process involves locating the device using its Serial Number (SN) via a third-party service, Easy4IPCloud:

1. The script queries the service to retrieve the device's status and IP address.
2. The service then communicates with the device to prepare it for connection.
3. Finally, the script establishes a connection with the device.

```mermaid
graph LR
  Device[Camera/NVR]
  App[[This script]]
  Client1[RTSP Client 1]
  Client2[RTSP Client 2]
  Clientn[RTSP Client n]
  Client1 -- TCP --> App
  Client2 -- TCP --> App
  Clientn -- TCP --> App
  App <-. UDP\nPTCP protocol .-> Device
```

Following the P2P handshake, the script begins to listen for RTSP connections on port 554. Upon a client's connection, the script initiates a new realm within the PTCP protocol. Essentially, this script serves as a tunnel between the client and the device, facilitating communication through PTCP encapsulation.

### P2P handshake

```mermaid
sequenceDiagram
  participant A as This script
  participant B as Easy4IPCloud
  participant C1 as P2P Server
  participant C2 as Relay Server
  participant C3 as Agent Server
  participant D as Camera/NVR

  A->>B: /probe/p2psrv
  B-->>A: ;
  A->>B: /online/p2psrv/{SN}
  B-->>A: p2psrv info

  A->>C1: /probe/device/{SN}
  C1-->>A: ;

  A->>C1: /info/device/{SN}
  C1-->>A: encrypted device info

  A->>B: /online/relay
  B-->>A: relay info

  A->>B: /device/{SN}/p2p-channel (*)

  par
    A->>C2: /relay/agent
    C2-->>A: agent info + token
    A->>C3: /relay/start/{token}
    C3-->>A: ;
  end

  B-->>A: device info

  A->>B: /device/{SN}/relay-channel + agent info

  C3-->>A: Server Nat Info!
  A->>C3: PTCP SYN
  A->>C3: PTCP request sign
  C3-->>A: PTCP sign

  A->>D: PTCP handshake (*)
```

_Note_: Both connections marked with `(*)` and all subsequent connections to the device must use the same UDP local port.

### Device info and the salt

`/info/device/{SN}` answers with the device's service ports and its password salt, wrapped in an `<Info>` element:

```xml
<body><DevVersion>6.7.11</DevVersion><Info>sJRI1JVcQjAKP/skwV5WD6+E9B+t...</Info></body>
```

The payload is base64 over AES-256-OFB. Unlike the per-session key used for `LocalAddr` encryption, this key and IV are fixed and shared by every device, so the payload decrypts to plain JSON:

```json
{
  "httpport": 80,
  "privport": 37777,
  "randsalt": "5daf91fc5cfc1be8e081cfb08f792726",
  "rtspport": 554,
  "tlsprivport": 37778
}
```

`randsalt` is the realm for the device password hash — `MD5("{username}:Login to {randsalt}:{password}")` — and is echoed back as `<RandSalt>` when authenticating the channel setup. It differs per device, so it has to be read from here rather than hardcoded.

Firmware that does not report its info answers with an empty `<Info></Info>`. Those devices have no salt: the hash realm collapses to `Login to `, and `<RandSalt>` is omitted from the auth body entirely.

### PTCP protocol

PTCP (PhonyTCP) is a proprietary protocol developed by Dahua. It serves the purpose of encapsulating TCP packets within UDP packets, enabling the creation of a tunnel between a client and a device behind a NAT.

Please note that official documentation for PTCP is not available. The information provided here is based on reverse engineering.

### PTCP packet header

The PTCP packet header is a fixed 24-byte structure, as outlined below:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             magic                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             sent                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             recv                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             pid                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             lmid                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             rmid                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- `magic`: A constant value, `PTCP`.
- `sent` and `recv`: Track the number of bytes sent and received, respectively.
- `pid`: The Packet ID.
- `lmid`: The Local ID.
- `rmid`: The Local ID of previously received packet.

### PTCP packet body

The packet body varies in size (0, 4, 12 bytes or more) based on the packet type. Its structure is as follows:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      type       |                     len                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             realm                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             padding                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- `type`: Specifies the packet type.
- `len`: The length of the `data` field.
- `realm`: The Realm ID of the connection.
- `padding`: Padding bytes, always set to 0.
- `data`: The packet data.

Packet types:

- Special:
  - Empty body
  - `0x00`: SYN, the body is always 4 bytes `0x00030100`.
- Realm:
  - `0x10`: TCP data, where `len` is the length of the TCP data.
  - `0x11`: Binding port request.
  - `0x12`: Connection status, where the data is either `CONN` or `DISC`.
- Common (with `realm` set to 0):
  - `0x13`: Heartbeat, where `len` is always 0.
  - `0x17`
  - `0x18`
  - `0x19`: Authentication.
  - `0x1a`: Server response after `0x19`.
  - `0x1b`: Client response after `0x1a`.

## Acknowledgments

This project has been inspired and influenced by the following projects and people:

- [mcw0/PoC](https://github.com/mcw0/PoC): The foundational structure for the handshake and the PTCP protocol.
- [@bpietroiu](https://github.com/bpietroiu): Recovered the easy4ip client credentials from SmartPSSLite in #9.
- [@p2p-sys](https://github.com/p2p-sys): The idea of inverting the STUN protocol, and finding the salt in the `/info/device` response in #13.
- [@mlebdd](https://github.com/mlebdd): Identified the `<Info>` payload as AES-OFB in #13.
- [@tguless](https://github.com/tguless): Supplied the Amcrest cloud endpoints and a test device in #17.
