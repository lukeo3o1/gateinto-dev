import ipaddress
import struct

SECTION_HEADER = 0x0A0D0D0A
INTERFACE_DESCRIPTION = 1
ENHANCED_PACKET = 6
BYTE_ORDER_MAGIC = 0x1A2B3C4D
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
IPV6_EXTENSIONS = (0, 43, 60)
IPV6_FRAGMENT = 44


def _transport(result, proto, data):
    if proto in (6, 17) and len(data) >= 4:
        result["sport"], result["dport"] = struct.unpack("!HH", data[:4])
    if proto == 6 and len(data) >= 14:
        flags = data[13]
        result.update(fin=bool(flags & 0x01), syn=bool(flags & 0x02), rst=bool(flags & 0x04), ack=bool(flags & 0x10))


def parse_ip(data):
    if not data:
        return None
    version = data[0] >> 4
    result = dict(v=version, sport=None, dport=None, syn=False, ack=False, fin=False, rst=False)
    if version == 4:
        header = (data[0] & 0x0F) * 4
        if len(data) < 20 or header < 20 or header > len(data):
            return None
        result.update(proto=data[9], tos=data[1], src=str(ipaddress.IPv4Address(data[12:16])),
                      dst=str(ipaddress.IPv4Address(data[16:20])))
        if struct.unpack("!H", data[6:8])[0] & 0x1FFF == 0:
            _transport(result, data[9], data[header:])
        return result
    if version == 6:
        if len(data) < 40:
            return None
        result.update(tos=((data[0] & 0x0F) << 4) | (data[1] >> 4),
                      src=str(ipaddress.IPv6Address(data[8:24])), dst=str(ipaddress.IPv6Address(data[24:40])))
        proto, offset, first_fragment = data[6], 40, True
        for _ in range(8):
            if proto not in IPV6_EXTENSIONS and proto != IPV6_FRAGMENT:
                break
            if offset + 8 > len(data):
                proto = None
                break
            if proto == IPV6_FRAGMENT:
                first_fragment = struct.unpack("!H", data[offset + 2:offset + 4])[0] & 0xFFF8 == 0
                proto, offset = data[offset], offset + 8
            else:
                proto, offset = data[offset], offset + (data[offset + 1] + 1) * 8
        result["proto"] = proto
        if proto is not None and offset <= len(data) and first_fragment:
            _transport(result, proto, data[offset:])
        return result
    return None


def _link_payload(linktype, data):
    if linktype in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6):
        return data
    if linktype != LINKTYPE_ETHERNET or len(data) < 14:
        return None
    ethertype, offset = struct.unpack("!H", data[12:14])[0], 14
    while ethertype in (0x8100, 0x88A8) and len(data) >= offset + 4:
        ethertype, offset = struct.unpack("!H", data[offset + 2:offset + 4])[0], offset + 4
    return data[offset:] if ethertype in (0x0800, 0x86DD) else None


def parse_pcapng(data, with_skipped=False):
    packets, skipped, offset, endian, interfaces = [], 0, 0, None, []
    while offset < len(data):
        if len(data) - offset < 12:
            raise ValueError("truncated block header")
        if struct.unpack("<I", data[offset:offset + 4])[0] == SECTION_HEADER:
            magic = data[offset + 8:offset + 12]
            if magic == struct.pack("<I", BYTE_ORDER_MAGIC):
                endian = "<"
            elif magic == struct.pack(">I", BYTE_ORDER_MAGIC):
                endian = ">"
            else:
                raise ValueError("invalid byte-order magic")
            interfaces = []
        elif endian is None:
            raise ValueError("missing section header")
        kind, total = struct.unpack(endian + "II", data[offset:offset + 8])
        if total < 12 or total % 4 or offset + total > len(data):
            raise ValueError("invalid block length")
        if struct.unpack(endian + "I", data[offset + total - 4:offset + total])[0] != total:
            raise ValueError("block length mismatch")
        body = data[offset + 8:offset + total - 4]
        if kind == INTERFACE_DESCRIPTION:
            if len(body) < 8:
                raise ValueError("short interface description")
            interfaces.append(struct.unpack(endian + "H", body[:2])[0])
        elif kind == ENHANCED_PACKET:
            if len(body) < 20:
                raise ValueError("short enhanced packet")
            interface, _, _, captured, _ = struct.unpack(endian + "IIIII", body[:20])
            if captured > len(body) - 20:
                raise ValueError("captured length exceeds block")
            payload = _link_payload(interfaces[interface], body[20:20 + captured]) if interface < len(
                interfaces) else None
            packet = parse_ip(payload) if payload is not None else None
            if packet is None:
                skipped += 1
            else:
                packets.append(packet)
        offset += total
    return (packets, skipped) if with_skipped else packets
