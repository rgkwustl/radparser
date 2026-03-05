import struct

class RadiusAttribute:
    def __init__(self, attr_type, value):
        self.type = attr_type
        self.value = value

    def __repr__(self):
        return f"RadiusAttribute(type={self.type}, value={self.value})"


class RadiusPacket:
    def __init__(self, code, identifier, authenticator, attributes):
        self.code = code
        self.identifier = identifier
        self.authenticator = authenticator
        self.attributes = attributes

    def __repr__(self):
        return (
            f"RadiusPacket(code={self.code}, id={self.identifier}, "
            f"authenticator={self.authenticator.hex()}, "
            f"attributes={self.attributes})"
        )


def parse_radius_packet(data: bytes) -> RadiusPacket:
    """
    Parse a raw RADIUS packet according to RFC 2865.
    """

    if len(data) < 20:
        raise ValueError("Packet too short to be a valid RADIUS message")

    # Unpack header: Code (1), Identifier (1), Length (2), Authenticator (16)
    code, identifier, length = struct.unpack("!BBH", data[:4])
    authenticator = data[4:20]

    if len(data) < length:
        raise ValueError("Packet length mismatch")

    attributes = []
    pos = 20

    while pos < length:
        if pos + 2 > length:
            raise ValueError("Malformed attribute header")

        attr_type = data[pos]
        attr_len = data[pos + 1]

        if attr_len < 2:
            raise ValueError("Invalid attribute length")

        if pos + attr_len > length:
            raise ValueError("Attribute length exceeds packet length")

        value = data[pos + 2 : pos + attr_len]
        attributes.append(RadiusAttribute(attr_type, value))

        pos += attr_len

    return RadiusPacket(code, identifier, authenticator, attributes)


# Example usage:
if __name__ == "__main__":
    # Example raw RADIUS Access-Request (dummy bytes)
    raw = (
        b"\x01\x0a\x00\x2c"  # Code=1, ID=10, Length=44
        b"\x00" * 16         # Authenticator
        b"\x01\x07" b"alice" # User-Name (Type 1, Len 7)
        b"\x02\x06" b"\x00\x12\x34\x56"  # User-Password (Type 2, Len 6)
    )

    pkt = parse_radius_packet(raw)
    print(pkt)
