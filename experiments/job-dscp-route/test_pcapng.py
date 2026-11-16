import ipaddress
import struct
import unittest

import pcapng


def ipv4_tcp(tos, sport, dport, flags=0x02, src="10.1.0.4", dst="192.0.2.1"):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 5 << 4, flags, 65535, 0, 0)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, tos, 20 + len(tcp), 0, 0, 128, 6, 0,
                         ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed)
    return header + tcp


def ipv6_udp(traffic_class, sport, dport, src="::1", dst="::1", hop_by_hop=False):
    udp = struct.pack("!HHHH", sport, dport, 8, 0)
    first = (6 << 28) | (traffic_class << 20)
    next_header = 0 if hop_by_hop else 17
    extension = bytes([17, 0, 0, 0, 0, 0, 0, 0]) if hop_by_hop else b""
    header = struct.pack("!IHBB16s16s", first, len(extension) + len(udp), next_header, 64,
                         ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed)
    return header + extension + udp


def ethernet(payload, ethertype=0x0800, vlan=False):
    prefix = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb"
    if vlan:
        return prefix + struct.pack("!HHH", 0x8100, 7, ethertype) + payload
    return prefix + struct.pack("!H", ethertype) + payload


def block(endian, kind, body):
    pad = (-len(body)) % 4
    total = 12 + len(body) + pad
    return struct.pack(endian + "II", kind, total) + body + b"\x00" * pad + struct.pack(endian + "I", total)


def section(endian):
    return block(endian, 0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1))


def interface(endian, linktype):
    return block(endian, 1, struct.pack(endian + "HHI", linktype, 0, 0))


def enhanced(endian, interface_id, data, original=None):
    original = len(data) if original is None else original
    return block(endian, 6, struct.pack(endian + "IIIII", interface_id, 0, 0, len(data), original) + data)


class IpParserTests(unittest.TestCase):
    def test_ipv4_tcp_fields(self):
        result = pcapng.parse_ip(ipv4_tcp(0x28 | 0x01, 50000, 443, flags=0x12))
        self.assertEqual(dict(v=4, proto=6, src="10.1.0.4", dst="192.0.2.1", sport=50000, dport=443, tos=0x29,
                              syn=True, ack=True, fin=False, rst=False), result)

    def test_ipv6_traffic_class_spans_nibbles(self):
        result = pcapng.parse_ip(ipv6_udp(0xB8, 1234, 53))
        self.assertEqual(0xB8, result["tos"])
        self.assertEqual((6, 17, 1234, 53), (result["v"], result["proto"], result["sport"], result["dport"]))
        self.assertEqual("::1", result["dst"])

    def test_ipv6_extension_header_is_skipped(self):
        result = pcapng.parse_ip(ipv6_udp(0x50, 1234, 53, hop_by_hop=True))
        self.assertEqual((17, 1234, 0x50), (result["proto"], result["sport"], result["tos"]))

    def test_truncated_transport_has_no_ports(self):
        result = pcapng.parse_ip(ipv4_tcp(40, 1, 2)[:22])
        self.assertEqual((6, None, None, 40), (result["proto"], result["sport"], result["dport"], result["tos"]))

    def test_garbage_is_rejected(self):
        for data in (b"", b"\x45", b"\x75" + b"\x00" * 40, b"\x60" + b"\x00" * 10):
            self.assertIsNone(pcapng.parse_ip(data))


class PcapngTests(unittest.TestCase):
    def capture(self, endian):
        return (section(endian) + interface(endian, 1) + interface(endian, 101)
                + enhanced(endian, 0, ethernet(ipv4_tcp(40, 50000, 443)))
                + enhanced(endian, 0, ethernet(ipv4_tcp(0, 50001, 443), vlan=True))
                + enhanced(endian, 1, ipv4_tcp(80, 50002, 443))
                + enhanced(endian, 0, ethernet(b"\x00" * 28, ethertype=0x0806))
                + block(endian, 5, b"\x00" * 8))

    def test_both_endiannesses(self):
        for endian in ("<", ">"):
            packets = pcapng.parse_pcapng(self.capture(endian))
            self.assertEqual([(50000, 40), (50001, 0), (50002, 80)], [(p["sport"], p["tos"]) for p in packets])

    def test_ipv6_over_ethernet_and_linktype_ipv6(self):
        data = (section("<") + interface("<", 1) + interface("<", 229)
                + enhanced("<", 0, ethernet(ipv6_udp(0x28, 7, 8), ethertype=0x86DD))
                + enhanced("<", 1, ipv6_udp(0x50, 9, 10)))
        self.assertEqual([(7, 0x28), (9, 0x50)], [(p["sport"], p["tos"]) for p in pcapng.parse_pcapng(data)])

    def test_unknown_interface_and_linktype_are_counted(self):
        data = (section("<") + interface("<", 147)
                + enhanced("<", 0, b"\x01\x02") + enhanced("<", 5, ipv4_tcp(0, 1, 2)))
        packets, skipped = pcapng.parse_pcapng(data, with_skipped=True)
        self.assertEqual([], packets)
        self.assertEqual(2, skipped)

    def test_new_section_resets_interfaces(self):
        data = (section("<") + interface("<", 101) + section(">") + interface(">", 1)
                + enhanced(">", 0, ethernet(ipv4_tcp(8, 1, 2))))
        self.assertEqual([8], [p["tos"] for p in pcapng.parse_pcapng(data)])

    def test_malformed_input_raises(self):
        for data in (b"\x00" * 12, section("<")[:-3], section("<") + struct.pack("<II", 6, 8),
                     section("<") + struct.pack("<II", 6, 0x7FFFFFF0) + b"\x00" * 8):
            with self.assertRaises(ValueError):
                pcapng.parse_pcapng(data)


if __name__ == "__main__":
    unittest.main()
