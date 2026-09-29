"""Deterministic, synthetic protocol fixtures. Never captures or transmits traffic."""
from pathlib import Path
import argparse
import ipaddress
import json
import struct

ROOT = Path(__file__).resolve().parents[1]

def checksum(data):
    data += b"\0" * (len(data) % 2)
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535

def ipv4(proto, payload, source="192.0.2.37", target="192.0.2.82", ident=1):
    src, dst = ipaddress.ip_address(source).packed, ipaddress.ip_address(target).packed
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0, src, dst)
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return bytes.fromhex("0200000000020200000000010800") + header + payload

def tcp(data, port, seq=101, flags=0x18, reverse=False, source="192.0.2.37"):
    src, dst = ("192.0.2.82", source) if reverse else (source, "192.0.2.82")
    a, b = (port, 51024) if reverse else (51024, port)
    segment = struct.pack("!HHIIBBHHH", a, b, seq, 0, 0x50, flags, 65535, 0, 0) + data
    pseudo = ipaddress.ip_address(src).packed + ipaddress.ip_address(dst).packed + struct.pack("!BBH", 0, 6, len(segment))
    segment = segment[:16] + struct.pack("!H", checksum(pseudo + segment)) + segment[18:]
    return ipv4(6, segment, src, dst)

def udp(data, port, source="192.0.2.37", target="192.0.2.82"):
    segment = struct.pack("!HHHH", 53000, port, len(data) + 8, 0) + data
    pseudo = ipaddress.ip_address(source).packed + ipaddress.ip_address(target).packed + struct.pack("!BBH", 0, 17, len(segment))
    segment = segment[:6] + struct.pack("!H", checksum(pseudo + segment) or 65535) + segment[8:]
    return ipv4(17, segment, source, target)

def pdu(kind, body):
    return bytes([kind, 0]) + struct.pack("!I", len(body)) + body

def block(kind, body):
    body += b"\0" * (-len(body) % 4)
    size = len(body) + 12
    return struct.pack("<II", kind, size) + body + struct.pack("<I", size)

def write_pcapng(path, packets):
    with path.open("wb") as file:
        file.write(block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
        for link in [1, 127]:
            file.write(block(1, struct.pack("<HHI", link, 0, 262144) + struct.pack("<HHBBBB", 9, 1, 9, 0, 0, 0) + bytes(4)))
        for i, (interface, packet) in enumerate(packets):
            ns = 1_000_000_000 + i * 10_000_000
            file.write(block(6, struct.pack("<IIIII", interface, ns >> 32, ns & 0xFFFFFFFF, len(packet), len(packet)) + packet))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "tests" / "fixtures")
    parser.add_argument("--scale", type=int, default=200)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    packets = []
    def stream(port, payload):
        packets.append((0, tcp(b"", port, 100, 2)))
        packets.append((0, tcp(payload, port)))
        packets.append((0, tcp(b"", port, 101 + len(payload), 0x11)))
    hl7 = b"\x0bMSH|^~\\&|DEMO|LAB|NETKIT|TEST|20260929||ORU^R01|DEMO-1|P|2.5\rPID|1||SYNTHETIC||EXAMPLE^PERSON\rOBX|1|ST|TEST||synthetic-result\r\x1c\r"
    packets += [(0, tcp(b"", 5100, 100, 2)), (0, tcp(hl7[17:], 5100, 118)), (0, tcp(hl7[:17], 5100)), (0, tcp(hl7[:17], 5100))]
    packets.append((0, tcp(b"", 5100, 2000, 0x12, True)))
    ack = b"\x0bMSH|^~\\&|NETKIT|TEST|DEMO|LAB|20260929||ACK|ACK-1|P|2.5\rMSA|AA|DEMO-1\r\x1c\r"
    packets.append((0, tcp(ack, 5100, 2001, reverse=True)))
    astm = b"1H|\\^&|||SYNTHETIC\rP|1|TEST\rR|1|GLU|42\rL|1|N\r\x03"
    stream(6201, b"\x02" + astm + f"{sum(astm) & 255:02X}\r\n".encode())
    stream(6202, b'<HEL.R01><DEV device_id="SYNTHETIC-DEVICE"/></HEL.R01><OBS.R01><OBS value="42"/></OBS.R01>')
    association = struct.pack("!HH", 1, 0) + b"TEST_PACS".ljust(16) + b"TEST_SCU".ljust(16) + bytes(32)
    command = bytes.fromhex("00000001020000003000")
    data = struct.pack("!I", len(command) + 2) + bytes([1, 3]) + command
    stream(6203, pdu(1, association) + pdu(4, data))
    stream(8080, b"GET /synthetic HTTP/1.1\r\nHost: example.test\r\nCookie: test-secret\r\n\r\n")
    stream(8081, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + bytes.fromhex("000003010400000001828684"))
    dns = bytes.fromhex("123481800001000100000000") + b"\x07example\x04test\0\0\x01\0\x01" + bytes.fromhex("c00c000100010000003c0004c0000201")
    packets.append((0, udp(dns, 53)))
    packets.append((0, udp(bytes.fromhex("c000000001080102030405060708080807060504030201") + bytes(16), 443)))
    arp = bytes.fromhex("ffffffffffff0200000000250806") + struct.pack("!HHBBH", 1, 0x800, 6, 4, 1) + bytes.fromhex("020000000025c0000225") + bytes(6) + bytes.fromhex("c0000252")
    packets.append((0, arp))
    beacon = bytes([0,0,8,0,0,0,0,0]) + bytes.fromhex("80000000ffffffffffff0200000000010200000000010000") + bytes(8) + bytes.fromhex("64000100") + b"\x00\x0bNETKIT_TEST"
    # SSID length is computed, avoiding any vendor or real network identifiers.
    beacon = beacon[:-13] + b"\x00" + bytes([len(b"NETKIT_TEST")]) + b"NETKIT_TEST"
    packets.append((1, beacon))
    write_pcapng(args.output / "clinical-network.pcapng", packets)
    (args.output / "synthetic.hl7").write_bytes(hl7)
    scaled = []
    for i in range(args.scale):
        source = str(ipaddress.ip_address("198.18.0.1") + i)
        scaled += [(0, tcp(b"", 5100, 100, 2, source=source)), (0, tcp(hl7, 5100, source=source))]
    write_pcapng(args.output / "scale.pcapng", scaled)
    print(json.dumps({"clinical_packets": len(packets), "scale_packets": len(scaled), "output": str(args.output)}))

if __name__ == "__main__":
    main()
