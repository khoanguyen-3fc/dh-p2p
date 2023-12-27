"""
DH-P2P + PTCP Implementation
"""
import argparse
import datetime
import random
import select
import socket
import subprocess
import sys
from urllib.parse import quote

from helpers import (
    MAIN_PORT,
    MAIN_SERVER,
    UDP,
    PTCPPayload,
    get_auth,
    get_dec,
    get_enc,
    get_key,
    get_nonce,
)


def main(serial, dtype=0, username=None, password=None, debug=False):
    socketserver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socketserver.bind(("0.0.0.0", 554))
    socketserver.listen(5)
    print("Listening on port 554")

    if debug:
        subprocess.Popen(
            [
                "ffplay",
                "-rtsp_transport",
                "tcp",
                "-i",
                f"rtsp://{username}:{quote(password)}@127.0.0.1/cam/realmonitor?channel=6&subtype=0",
            ]
        )

    main_remote = UDP(MAIN_SERVER, MAIN_PORT, debug)
    res = main_remote.request("/probe/p2psrv")

    res = main_remote.request(f"/online/p2psrv/{serial}")

    p2psrv_server, p2psrv_port = res["data"]["body"]["US"].split(":")
    p2psrv_port = int(p2psrv_port)

    p2psrv_remote = UDP(p2psrv_server, p2psrv_port, debug)
    res = p2psrv_remote.request(f"/probe/device/{serial}")
    p2psrv_remote.close()

    res = main_remote.request("/online/relay")
    relay_server, relay_port = res["data"]["body"]["Address"].split(":")
    relay_port = int(relay_port)

    device_remote = UDP(MAIN_SERVER, MAIN_PORT, debug)

    laddr = f"127.0.0.1:{device_remote.lport}"
    ipaddr = f"<IpEncrpt>true</IpEncrpt><LocalAddr>{laddr}</LocalAddr>"
    auth = ""
    aid = random.randbytes(8)

    if dtype > 0:
        key = get_key(username, password)
        nonce = get_nonce()

        laddr = get_enc(key, nonce, laddr)
        ipaddr = f"<IpEncrptV2>true</IpEncrptV2><LocalAddr>{laddr}</LocalAddr>"
        auth = "" if dtype == 0 else get_auth(username, key, nonce, laddr)

    res = device_remote.request(
        f"/device/{serial}/p2p-channel",
        f"<body>{auth}<Identify>{' '.join(f'{b:x}' for b in aid)}</Identify>{ipaddr}<version>5.0.0</version></body>",
        should_read=False,
    )

    main_remote.rhost = relay_server
    main_remote.rport = relay_port
    res = main_remote.request("/relay/agent")
    token = res["data"]["body"]["Token"]
    agent_server, agent_port = res["data"]["body"]["Agent"].split(":")
    agent_port = int(agent_port)

    main_remote.rhost = agent_server
    main_remote.rport = agent_port
    res = main_remote.request(
        f"/relay/start/{token}",
        "<body><Client>:0</Client></body>",
    )

    res = device_remote.read(return_error=True)
    if res["code"] < 200:
        res = device_remote.read(return_error=True)

    if res["code"] >= 400:
        print("Error:", res["status"])

        if dtype == 0 and res["code"] == 403:
            print("Device requires authentication when creating P2P channel.")
            print("Try again with:")
            print(
                f"main.py --type 1 --username <username> --password <password> {serial}"
            )

        sys.exit(1)

    device_laddr = res["data"]["body"]["LocalAddr"]
    if dtype > 0:
        nonce = res["data"]["body"]["Nonce"]
        device_laddr = get_dec(key, nonce, device_laddr)

    device_server, device_port = res["data"]["body"]["PubAddr"].split(":")
    device_port = int(device_port)
    device_remote.rhost = device_server
    device_remote.rport = device_port

    main_remote.rhost = MAIN_SERVER
    main_remote.rport = MAIN_PORT

    if dtype > 0:
        auth = get_auth(username, key, nonce)

    res = main_remote.request(
        f"/device/{serial}/relay-channel",
        f"<body>{auth}<agentAddr>{agent_server}:{agent_port}</agentAddr></body>",
        should_read=False,
    )

    main_remote.rhost = agent_server
    main_remote.rport = agent_port
    # TODO: check timeout
    res = main_remote.read()

    main_remote.request_ptcp(b"\x00\x03\x01\x00")
    res = main_remote.read_ptcp()

    main_remote.request_ptcp(b"\x17\x00\x00\x00" + b"\x00\x00\x00\x00\x00\x00\x00\x00")
    res = main_remote.read_ptcp()
    while len(res.body) == 0:
        res = main_remote.read_ptcp()
    sign = res.body[12:]

    main_remote.request_ptcp()

    device_remote.rhost = device_server
    device_remote.rport = device_port

    aid = bytes(0xFF - b for b in aid)
    cookie = random.randbytes(4)
    trasn_id = random.randbytes(12)
    eaddr = device_port.to_bytes(2) + socket.inet_aton(device_server)
    eaddr = bytes(0xFF - b for b in eaddr)

    data = (
        b"\xff\xfe\xff\xe7"
        + cookie
        + trasn_id
        + b"\x7f\xd5\xff\xf7"
        + aid
        + b"\xff\xfb\xff\xf7\xff\xfe"
        + eaddr
    )
    print(f":{device_remote.lport} >>> {device_remote.rhost}:{device_remote.rport}")
    print("".join(f"\\x{b:02X}" for b in data))
    device_remote.send(data)

    try:
        data = device_remote.recv(timeout=5)
    except socket.timeout:
        print("Timeout occurred while waiting for a response from the device.")
        print("If the issue persists, you may need to use relay mode with this device.")
        print("Note: Relay mode is currently not implemented for Python.")
        sys.exit(1)

    print("Data <<<")
    print("".join(f"\\x{b:02X}" for b in data))

    rtrans_id = data[8:20]
    ip, port = device_laddr.split(":")
    port = int(port)
    eaddr = port.to_bytes(2) + socket.inet_aton(ip)

    data = (
        b"\xfe\xfe\xff\xe7"
        + cookie
        + rtrans_id
        + b"\x7f\xd6\xff\xf7"
        + aid
        + b"\xff\xfb\xff\xf7\xff\xfe"
        + eaddr
    )
    print("Request >>>")
    print("".join(f"\\x{b:02X}" for b in data))
    device_remote.send(data)

    if dtype > 0:
        data = device_remote.recv()
        print("Data <<<")
        print("".join(f"\\x{b:02X}" for b in data))

        data = (
            b"\xfe\xfe\xff\xf3"
            + cookie
            + rtrans_id
            + b"\x7f\xd6\xff\xf7"
            + aid
            + b"\xff\xfb\xff\xf7\xff\xfe"
            + b"\xa8\x13\x3f\x57\xfe\x37"
        )

        for _ in range(5):
            print("Request >>>")
            print("".join(f"\\x{b:02X}" for b in data))
            device_remote.send(data)

    for _ in range(5):
        data = device_remote.recv()
        print("Data <<<")
        print("".join(f"\\x{b:02X}" for b in data))

    device_remote.request_ptcp(b"\x00\x03\x01\x00")
    res = device_remote.read_ptcp()
    assert res.body == b"\x00\x03\x01\x00"

    device_remote.request_ptcp(
        b"\x19\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + sign
    )
    res = device_remote.read_ptcp()
    if len(res.body) == 0:
        res = device_remote.read_ptcp()
    assert res.body[0] == 0x1A

    device_remote.request_ptcp(
        b"\x1b\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00"
    )
    res = device_remote.read_ptcp()
    assert len(res.body) == 0

    print("Ready to connect")
    print("Test with: rtsp://127.0.0.1/cam/realmonitor?channel=1&subtype=0")
    while True:
        ready, _, _ = select.select([socketserver], [], [], 0.1)

        if not ready:
            ptcp_ready, _, _ = select.select([device_remote], [], [], 0)

            if not ptcp_ready:
                continue

            # TODO: only simplex, need to implement duplex
            res = device_remote.read_ptcp()
            if len(res.body) == 0:
                continue

            assert res.body[0] == 0x13
            device_remote.request_ptcp()

            continue

        socketclient, address = socketserver.accept()
        print(f"Connection from {address}")

        realm_id = random.randint(0x00000000, 0xFFFFFFFF)
        device_remote.request_ptcp(
            b"\x11\x00\x00\x00"
            + realm_id.to_bytes(4, "big")
            + b"\x00\x00\x00\x00"
            # port 554
            + b"\x00\x00\x02\x2A"
            + b"\x7f\x00\x00\x01",
        )
        res = device_remote.read_ptcp()
        if len(res.body) == 0:
            res = device_remote.read_ptcp()
        assert res.body[0] == 0x12

        try:
            while True:
                ptcp_ready, _, _ = select.select([device_remote], [], [], 0.1)

                # if ptcp_ready:
                while ptcp_ready:
                    res = device_remote.read_ptcp()

                    if len(res.body) == 0:
                        continue

                    device_remote.request_ptcp()

                    if res.body[0] != 0x10:
                        continue

                    body = PTCPPayload.parse(res.body)

                    if debug:
                        print()
                        print(body)
                        print(f"[{datetime.datetime.now().isoformat()}]")
                        print("Data <<<")
                        print(body.payload)
                        print()

                    socketclient.send(body.payload)

                    ptcp_ready, _, _ = select.select([device_remote], [], [], 0.1)

                client_ready, _, _ = select.select([socketclient], [], [], 0)

                if not client_ready:
                    continue

                data = socketclient.recv(4096)

                if not data:
                    print("Connection closed?")
                    break

                if debug:
                    print()
                    print(f"[{datetime.datetime.now().isoformat()}]")
                    print("Data >>>")
                    print(data)
                    print()

                device_remote.request_ptcp(bytes(PTCPPayload(realm_id, data)))

        # handle connection reset by peer
        except ConnectionResetError:
            print("Connection reset by peer")
        except BrokenPipeError:
            print("Broken pipe")
        finally:
            print("Cleaning up connection")
            device_remote.request_ptcp(
                b"\x12\x00\x00\x00"
                + realm_id.to_bytes(4, "big")
                + b"\x00\x00\x00\x00"
                + b"DISC"
            )

            res = device_remote.read_ptcp()

            while len(res.body) == 0 or res.body[0] == 0x10:
                if len(res.body) > 0:
                    device_remote.request_ptcp()

                res = device_remote.read_ptcp()

            assert res.body[0] == 0x12
            device_remote.request_ptcp()

            socketclient.close()
            print("Connection closed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("serial", help="Serial number of the camera")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("-t", "--type", type=int, help="Type of the camera", default=0)
    parser.add_argument("-u", "--username", help="Username of the camera")
    parser.add_argument("-p", "--password", help="Password of the camera")
    args = parser.parse_args()

    if args.username is None or args.password is None:
        if args.type > 0:
            parser.error("Username and password are required for type > 0")
        elif args.debug:
            parser.error("Username and password are required in debug mode")

    if args.serial:
        main(args.serial, args.type, args.username, args.password, args.debug)
