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

[WIP]
