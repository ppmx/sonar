#!/usr/bin/env python3

import argparse
import base64
import datetime
import enum
import hashlib
import json
import os
import select
import socket
import struct
import threading
import time
import typing

from Crypto.Cipher import Salsa20

class SonarMsgType(enum.IntEnum):
    """ Specifying the type of the sonar message - used in the protocol's header """

    BROADCAST = enum.auto()
    BROADCAST_REPLY = enum.auto()

class SonarParserException(Exception):
    """ Used to propagate any error that occurs during parsing an
    incoming (maybe even non-sonar) message.
    """

class SonarMessaging:
    """ Protocol implementation """

    def __init__(self):
        self.magic = bytes.fromhex("F09F928C")
        self.version = 1

    def _parse_message(self, raw_data: bytes, ensure_msg_type=None) -> tuple[SonarMsgType, dict]:
        if not raw_data.startswith(self.magic):
            raise SonarParserException()

        version, msg_type = struct.unpack(">BB", raw_data[4:6])

        if version != self.version:
            raise SonarParserException()

        if ensure_msg_type and msg_type != ensure_msg_type:
            raise SonarParserException()

        data = json.loads(base64.b64decode(raw_data[6:]))
        return msg_type, data

    def parse_broadcast(self, raw_data: bytes) -> tuple[str, bytes]:
        """ Parses a broadcast message - returns hostname and payload. Raises a
        SonarParserException for any raw_data that doesnt represent a sonar broadcast.
        """

        _, data = self._parse_message(raw_data, SonarMsgType.BROADCAST)
        return data["hostname"], base64.b64decode(data["payload"])

    def gen_broadcast(self, hostname: str, payload: bytes) -> bytes:
        """ Generate a complete sonar broadcast packet """

        data = {"hostname": hostname, "payload": base64.b64encode(payload).decode()}

        msg = b""
        msg += self.magic
        msg += struct.pack(">BB", self.version, SonarMsgType.BROADCAST)
        msg += base64.b64encode(json.dumps(data).encode())
        return msg

class SonarEncryptedMessaging(SonarMessaging):
    def __init__(self, transport_key: bytes):
        self.__key = hashlib.md5(transport_key).digest()
        super().__init__()

    def parse_broadcast(self, raw_data: bytes) -> tuple[str, dict]:
        return super().parse_broadcast(self._decrypt(raw_data))

    def gen_broadcast(self, hostname: str, payload: bytes) -> bytes:
        return self._encrypt(super().gen_broadcast(hostname, payload))

    def _encrypt(self, plaintext: bytes) -> bytes:
        cipher = Salsa20.new(key=self.__key)
        return cipher.nonce + cipher.encrypt(plaintext)

    def _decrypt(self, message: bytes) -> bytes:
        return Salsa20.new(key=self.__key, nonce=message[:8]).decrypt(message[8:])

class SonarDriver(threading.Thread):
    def __init__(self, port: int, payload: bytes, key: str = None, participate: bool = True):
        self.port = port
        self.broadcast_addr = "255.255.255.255"
        self.hostname = socket.gethostname()
        self.__shutdown_requested = threading.Event()

        self.enforce_beaconing = threading.Event()
        self.beacon_interval = datetime.timedelta(seconds=10)
        self.ts_beacon_sent = None

        self.active_beaconing = participate
        self.payload = payload

        self.msging = SonarEncryptedMessaging(key) if key else SonarMessaging()
        self.active_peers_storage = PeersStorage(deadline=self.beacon_interval)

        super().__init__()

    def shutdown(self):
        self.__shutdown_requested.set()

    def get_active_peers(self):
        return self.active_peers_storage.get_active_peers()

    def run(self) -> None:
        self.active_peers_storage.start()
        return self.serve_forever()

    def serve_forever(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("", self.port))

        while not self.__shutdown_requested.is_set():
            self.do_beaconing()
            self.handle_rx(sock)

        self.active_peers_storage.shutdown()
        self.active_peers_storage.join()

    def do_beaconing(self) -> None:
        if not self.active_beaconing:
            return

        if self.ts_beacon_sent:
            is_due = (datetime.datetime.now() - self.ts_beacon_sent) > self.beacon_interval
        else:
            is_due = True

        if self.enforce_beaconing.is_set() or is_due:
            self.enforce_beaconing.clear()
            self.send_beacon()

    def handle_rx(self, sock) -> None:
        ready_socks = select.select([sock], [], [], 1)
        if len(ready_socks[0]) == 0:
            return

        pkt, incoming_addr = sock.recvfrom(4096)

        try:
            hostname, payload = self.msging.parse_broadcast(pkt)
        except SonarParserException:
            return

        if hostname == self.hostname:
            return

        ip = incoming_addr[0]
        self.active_peers_storage.handle_beacon(ip, payload, hostname)

    def send_beacon(self) -> None:
        brd_msg = self.msging.gen_broadcast(self.hostname, self.payload)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(brd_msg, (self.broadcast_addr, self.port))
        sock.close()

        self.ts_beacon_sent = datetime.datetime.now()

class SonarPeer:
    def __init__(self, ipaddr: str, payload: bytes, hostname: str, peer_id: str):
        self.ipaddr = ipaddr
        self.hostname = hostname
        self.peer_id = peer_id
        self.payload = payload

        self.last_update = None
        self.update()

    def update(self, payload=None):
        self.last_update = datetime.datetime.now()

        if payload:
            self.payload = payload

    def __str__(self):
        return f"{self.hostname}@{self.ipaddr} ({self.payload})"

class PeersStorage(threading.Thread):
    def __init__(self, deadline=datetime.timedelta(seconds=120)):
        self.deadline = deadline
        self.active_peers = {}
        self.__shutdown_requested = threading.Event()
        super().__init__()

    def shutdown(self):
        self.__shutdown_requested.set()

    def get_active_peers(self) -> list[SonarPeer]:
        return self.active_peers.values()

    def cleanup(self):
        list_old_peers = []

        for peer_id, peer in self.active_peers.items():
            if (peer.last_update + self.deadline) < datetime.datetime.now():
                list_old_peers.append(peer_id)

        for old_peer in list_old_peers:
            del self.active_peers[old_peer]

    def run(self) -> None:
        while not self.__shutdown_requested.is_set():
            self.cleanup()
            time.sleep(self.deadline.total_seconds() // 2)

    def generate_peer_id(self, ipaddr: str, payload: bytes, hostname: str) -> str:
        return hashlib.sha256(f"{ipaddr}-{hostname}".encode()).hexdigest()

    def handle_beacon(self, ipaddr: str, payload: bytes, hostname: str) -> None:
        peer_id = self.generate_peer_id(ipaddr, payload, hostname)

        if peer_id in self.active_peers:
            self.active_peers[peer_id].update(payload)
        else:
            self.active_peers[peer_id] = SonarPeer(ipaddr, payload, hostname, peer_id)

def load_age_pubkey(privkey_path="~/.config/Sonar/private_key.age") -> typing.Optional[str]:
    """ Load an age public key from an age private key file. """

    with open(os.path.expanduser(privkey_path)) as key_reader:
        for line in key_reader:
            if line.startswith("# public key: "):
                return line.split(' ')[3].strip()

    return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", type=int, default=1337)
    parser.add_argument("--payload", type=lambda x: x.encode())
    parser.add_argument("--listen-only", action="store_true")
    parser.add_argument("-k", "--key", type=bytes.fromhex)
    args = parser.parse_args()

    print(r"             __                                                             ")
    print(r"         __  \ \       _______. ______  .__   __.     ___     .______       ")
    print(r"     __  \ \ | |      /       |/  __  \ |  \ |  |    /   \    |   _  \      ")
    print(r"     \ \ | | | |     |   (----|  |  |  ||   \|  |   /  ^  \   |  |_)  |     ")
    print(r"     | | | | | |      \   \   |  |  |  ||  . `  |  /  /_\  \  |      /      ")
    print(r"    /_/  | | | |   .---)   |  |  `--'  ||  |\   | /  _____  \ |  |\  \--.   ")
    print(r"        /_/  | |   |______/    \______/ |__| \__|/__/     \__\| _| `.___|   ")
    print(r"             /_/                                                            ")
    print(r"                                                                            ")
    print(r"                                                                            ")

    payload = args.payload or load_age_pubkey().encode() or "undefined"
    print(f"[*] using payload {payload}")

    rp = SonarDriver(
        args.port,
        payload=payload,
        key=args.key,
        participate=not args.listen_only
    )

    rp.start()


    try:
        while True:
            active_peers = rp.get_active_peers()

            print(datetime.datetime.now().ctime(), f"- {len(active_peers)} peers active")
            for peer in active_peers:
                print(" " * 24, peer)

            time.sleep(10)
    except KeyboardInterrupt:
        print("[*] shutting down")
        rp.shutdown()

if __name__ == "__main__":
    main()
