#!/usr/bin/env python3
"""Minimal TCP xApp for the ns-3 LTE PDCP inspection hook."""

import argparse
import hashlib
import json
import math
import socket
import struct
from collections import Counter
from ipaddress import IPv4Address, IPv6Address


def format_hex(payload: bytes) -> str:
    return payload.hex(" ")


def printable_preview(payload: bytes) -> str:
    return "".join(chr(byte) if 32 <= byte < 127 else "." for byte in payload)


def entropy(payload: bytes) -> float:
    if not payload:
        return 0.0
    counts = Counter(payload)
    length = len(payload)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def parse_transport(payload: bytes, protocol: int) -> dict:
    if protocol == 6 and len(payload) >= 20:
        source, destination, sequence, acknowledgment, offset_flags, window, checksum, urgent = (
            struct.unpack("!HHIIHHHH", payload[:20])
        )
        header_length = (offset_flags >> 12) * 4
        flags = offset_flags & 0x01FF
        return {
            "protocol": "TCP",
            "source_port": source,
            "destination_port": destination,
            "sequence": sequence,
            "acknowledgment": acknowledgment,
            "header_length": header_length,
            "flags": {
                name: bool(flags & value)
                for name, value in (
                    ("FIN", 0x001),
                    ("SYN", 0x002),
                    ("RST", 0x004),
                    ("PSH", 0x008),
                    ("ACK", 0x010),
                    ("URG", 0x020),
                    ("ECE", 0x040),
                    ("CWR", 0x080),
                    ("NS", 0x100),
                )
            },
            "window": window,
            "checksum": f"0x{checksum:04x}",
            "urgent_pointer": urgent,
            "options_hex": payload[20:header_length].hex(),
        }
    if protocol == 17 and len(payload) >= 8:
        source, destination, length, checksum = struct.unpack("!HHHH", payload[:8])
        return {
            "protocol": "UDP",
            "source_port": source,
            "destination_port": destination,
            "length": length,
            "checksum": f"0x{checksum:04x}",
        }
    if protocol == 1 and len(payload) >= 4:
        icmp_type, code, checksum = struct.unpack("!BBH", payload[:4])
        return {
            "protocol": "ICMP",
            "type": icmp_type,
            "code": code,
            "checksum": f"0x{checksum:04x}",
        }
    return {"protocol_number": protocol, "raw_header_hex": payload[:40].hex()}


def parse_packet(payload: bytes) -> dict:
    if not payload:
        return {"network_protocol": "empty"}

    version = payload[0] >> 4
    if version == 4 and len(payload) >= 20:
        version_ihl, dscp_ecn, total_length, identification, flags_fragment, ttl, protocol, checksum, source, destination = struct.unpack(
            "!BBHHHBBH4s4s", payload[:20]
        )
        ihl = (version_ihl & 0x0F) * 4
        fragment_offset = flags_fragment & 0x1FFF
        result = {
            "network_protocol": "IPv4",
            "version": 4,
            "header_length": ihl,
            "dscp": dscp_ecn >> 2,
            "ecn": dscp_ecn & 0x03,
            "total_length": total_length,
            "identification": identification,
            "flags": {
                "reserved": bool(flags_fragment & 0x8000),
                "dont_fragment": bool(flags_fragment & 0x4000),
                "more_fragments": bool(flags_fragment & 0x2000),
            },
            "fragment_offset": fragment_offset,
            "ttl": ttl,
            "protocol": protocol,
            "header_checksum": f"0x{checksum:04x}",
            "source": str(IPv4Address(source)),
            "destination": str(IPv4Address(destination)),
            "options_hex": payload[20:ihl].hex(),
        }
        if fragment_offset == 0:
            result["transport"] = parse_transport(payload[ihl:], protocol)
        return result

    if version == 6 and len(payload) >= 40:
        first_word, payload_length, next_header, hop_limit = struct.unpack(
            "!IHBB", payload[:8]
        )
        source = IPv6Address(payload[8:24])
        destination = IPv6Address(payload[24:40])
        return {
            "network_protocol": "IPv6",
            "version": 6,
            "traffic_class": (first_word >> 20) & 0xFF,
            "flow_label": first_word & 0xFFFFF,
            "payload_length": payload_length,
            "next_header": next_header,
            "hop_limit": hop_limit,
            "source": str(source),
            "destination": str(destination),
            "note": "IPv6 extension headers are retained in raw_hex and are not traversed",
        }

    return {
        "network_protocol": "unknown",
        "first_byte": f"0x{payload[0]:02x}",
        "raw_header_hex": payload[:40].hex(),
    }


def describe_packet(report: dict) -> None:
    payload_hex = report.get("payload_hex", "")
    try:
        payload = bytes.fromhex(payload_hex)
    except ValueError:
        print("payload_hex inválido; não foi possível decodificar o pacote")
        return

    print("=" * 100)
    print("RELATÓRIO JSON COMPLETO:")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    print(f"payload_length_decoded: {len(payload)}")
    print(f"payload_sha256: {hashlib.sha256(payload).hexdigest()}")
    print(f"payload_entropy_bits_per_byte: {entropy(payload):.4f}")
    print(f"payload_unique_bytes: {len(set(payload))}/256")
    print(f"payload_printable_ratio: {sum(32 <= byte < 127 for byte in payload) / len(payload) if payload else 0:.4f}")
    print(f"payload_ascii_preview: {printable_preview(payload)}")
    print("payload_hex:")
    print(format_hex(payload))
    print("DECODED_HEADERS:")
    print(json.dumps(parse_packet(payload), indent=2, ensure_ascii=False))


def handle_client(connection: socket.socket) -> None:
    with connection, connection.makefile("r", encoding="utf-8") as stream:
        for line in stream:
            try:
                report = json.loads(line)
                print(
                    f"{report.get('direction')} packet: "
                    f"{report.get('size')} bytes, RNTI={report.get('rnti')}"
                )
                describe_packet(report)
                # Placeholder policy: every packet is allowed for now.
                response = {"action": "allow"}
            except json.JSONDecodeError:
                response = {"action": "allow", "error": "invalid-json"}
            connection.sendall((json.dumps(response) + "\n").encode("utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9999)
    args = parser.parse_args()

    with socket.create_server((args.host, args.port), reuse_port=False) as server:
        print(f"xApp listening on {args.host}:{args.port}")
        while True:
            connection, address = server.accept()
            print(f"connected: {address}")
            handle_client(connection)


if __name__ == "__main__":
    main()
