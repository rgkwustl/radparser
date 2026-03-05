import struct

RADIUS_ATTRIBUTE_TYPES = {
    1:  "User-Name",
    2:  "User-Password",
    3:  "CHAP-Password",
    4:  "NAS-IP-Address",
    5:  "NAS-Port",
    6:  "Service-Type",
    7:  "Framed-Protocol",
    8:  "Framed-IP-Address",
    9:  "Framed-IP-Netmask",
    10: "Framed-Routing",
    11: "Filter-Id",
    12: "Framed-MTU",
    13: "Framed-Compression",
    14: "Login-IP-Host",
    15: "Login-Service",
    16: "Login-TCP-Port",
    18: "Reply-Message",
    19: "Callback-Number",
    20: "Callback-Id",
    22: "Framed-Route",
    23: "Framed-IPX-Network",
    24: "State",
    25: "Class",
    26: "Vendor-Specific",
    27: "Session-Timeout",
    28: "Idle-Timeout",
    29: "Termination-Action",
    30: "Called-Station-Id",
    31: "Calling-Station-Id",
    32: "NAS-Identifier",
    33: "Proxy-State",
    34: "Login-LAT-Service",
    35: "Login-LAT-Node",
    36: "Login-LAT-Group",
    37: "Framed-AppleTalk-Link",
    38: "Framed-AppleTalk-Network",
    39: "Framed-AppleTalk-Zone",
}


class RadiusPacket:
    def __init__(self, code, identifier, authenticator, attributes=None):
        self.code = code
        self.identifier = identifier
        self.authenticator = authenticator
        self.attributes = attributes or {}

    def add_attribute(self, attr_type, value: bytes):
        self.attributes.setdefault(attr_type, []).append(value)

    def get_attribute(self, attr_type):
        return self.attributes.get(attr_type, [])

    def set_attribute(self, attr_type, value):
        if not isinstance(value, bytes):
            value = str(value).encode()
        self.attributes[attr_type] = [value]

    def to_bytes(self):
        body = b""
        for attr_type, values in self.attributes.items():
            for v in values:
                body += struct.pack("!BB", attr_type, len(v) + 2) + v

        length = 20 + len(body)
        header = struct.pack("!BBH", self.code, self.identifier, length) + self.authenticator
        return header + body


def _normalize(name):
    return name.lower().replace("-", "_")


def _install_accessors():
    for attr_type, name in RADIUS_ATTRIBUTE_TYPES.items():
        pyname = _normalize(name)

        def make_getter(t):
            return lambda self: self.get_attribute(t)

        def make_setter(t):
            return lambda self, v: self.set_attribute(t, v)

        setattr(RadiusPacket, f"get_{pyname}", make_getter(attr_type))
        setattr(RadiusPacket, f"set_{pyname}", make_setter(attr_type))


_install_accessors()
