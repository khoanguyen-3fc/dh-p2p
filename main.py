"""
DH-P2P + PTCP Implementation
"""
import argparse
import datetime
import random
import select
import socket
import subprocess
from urllib.parse import quote

from helpers import MAIN_PORT, MAIN_SERVER, UDP, PTCPPayload


def main(serial, username=None, password=None, debug=False):
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
    res = device_remote.request(
        f"/device/{serial}/p2p-channel",
        f"<body><Identify>d4 9e 67 a8 2b d4 7e 1e</Identify><IpEncrpt>true</IpEncrpt><LocalAddr>63.87.143.254,63.87.254.173:{device_remote.lport}</LocalAddr><version>5.0.0</version></body>",
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

    res = device_remote.read()
    if res["code"] != 200:
        res = device_remote.read()

    device_server, device_port = res["data"]["body"]["PubAddr"].split(":")
    device_port = int(device_port)
    device_remote.rhost = device_server
    device_remote.rport = device_port

    main_remote.rhost = MAIN_SERVER
    main_remote.rport = MAIN_PORT
    res = main_remote.request(
        f"/device/{serial}/relay-channel",
        f"<body><agentAddr>{agent_server}:{agent_port}</agentAddr></body>",
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

    data = b"\xff\xfe\xff\xe7\xde\xed\x5b\xbd\xb3\x03\xef\x13\x41\x2b\x12\xae\xf9\xba\xb2\x66\x7f\xd5\xff\xf7\x2b\x61\x98\x57\xd4\x2b\x81\xe1\xff\xfb\xff\xf7\xff\xfe\xa8\x13\x21\x02\xd2\x65"
    print(f":{device_remote.lport} >>> {device_remote.rhost}:{device_remote.rport}")
    print("".join(f"\\x{b:02X}" for b in data))
    device_remote.send(data)

    # TODO: check timeout
    data = device_remote.recv()
    print("Data <<<")
    print("".join(f"\\x{b:02X}" for b in data))

    data = b"\xfe\xfe\xff\xe7\xde\xed\x5b\xbd\xd3\xfa\x95\xab\x92\x98\xc8\xe0\x6b\x6e\x84\x4e\x7f\xd6\xff\xf7\x2b\x61\x98\x57\xd4\x2b\x81\xe1\xff\xfb\xff\xf7\xff\xfe\xa8\x13\x3f\x57\xfe\x37"
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
    parser.add_argument("-u", "--username", help="Username of the camera")
    parser.add_argument("-p", "--password", help="Password of the camera")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode")
    args = parser.parse_args()

    if args.serial:
        main(args.serial, args.username, args.password, args.debug)
