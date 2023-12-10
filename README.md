# RTSP over Dahua P2P (a.k.a. PTCP / PhonyTCP) protocol

This is a proof of concept implementation of RTSP over Dahua P2P protocol. It works with Dahua and derived cameras / NVRs.

## Files

- `requirements.txt` - python dependencies
- `main.py` - main script
- `helpers.py` - helper functions
- `ptcp.lua` - WireShark dissector for Dahua P2P protocol

## Setup

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

## Usage

`USERNAME` and `PASSWORD` only need for debug mode and `ffplay` is required.

```text
usage: main.py [-h] [-u USERNAME] [-p PASSWORD] [-d] serial

positional arguments:
  serial                Serial number of the camera

options:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        Username of the camera
  -p PASSWORD, --password PASSWORD
                        Password of the camera
  -d, --debug           Enable debug mode
```

## Limitations

- Single threaded, so only one client can connect at a time
- Not fully implemented (e.g. only simplex keep-alive, no mulpile connections, etc.)
- Work better with `ffplay` and `-rtsp_transport tcp` option
- Still unstable, can crash at any time

## Protocol description

For reverse engineering the protocol, I used [Wireshark](https://www.wireshark.org/) and [KBiVMS V2.02.0](https://kbvisiongroup.com/support/download-center.html) as a client on Windows. Using `ptcp.lua` dissector, you can see the protocol in Wireshark easier.

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
  Client[RTSP Client]
  Client -- TCP --> App
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
  A->>B: /online/p2psrv/{SN}
  B-->>A: p2psrv info

  A->>C1: /probe/device/{SN}

  A->>B: /online/relay
  B-->>A: relay info

  A->>B: /device/{SN}/p2p-channel (*)

  A->>C2: /relay/agent
  C2-->>A: agent info + token

  A->>C3: /relay/start/{token}
  C3-->>A: device info

  A->>B: /device/{SN}/relay-channel + agent info

  C3-->>A: PTCP SYN
  A->>C3: PTCP SYN-ACK
  A->>C3: PTCP request sign
  C3-->>A: PTCP sign

  A->>D: PTCP handshake (*)
```

_Note_: Both connections marked with `(*)` and all subsequent connections to the device must use the same UDP local port.

### PTCP protocol

[WIP]
