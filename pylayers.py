import io
import struct
from socket import inet_aton
import abc


IPV4_EVIL_BIT = 1 << 2
IPV4_DONT_FRAGMENT = 1 << 1
IPV4_MORE_FRAGMENTS = 1 << 0


class Layer(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def set_length(self, payload_length: int) -> None:
        """\
        set the total length of the layer by specifing the payload length
        """
        raise NotImplementedError

    @abc.abstractmethod
    def get_total_length(self) -> int:
        """\
        get the total length of the layer (header + payload)
        """
        raise NotImplementedError

    @abc.abstractmethod
    def get_payload_length(self) -> int:
        """\
        get the length of the payload
        """
        raise NotImplementedError

    @abc.abstractmethod
    def has_checksum(self) -> bool:
        """\
        returns if the layer has a checksum that need to be calculated or not
        """
        raise NotImplementedError

    @abc.abstractmethod
    def serialize(self, buf: io.BytesIO) -> None:
        """\
        serialize the layer into an io buffer
        """
        raise NotImplementedError


class IPv4Layer(Layer):
    def __init__(self, protocol: int, src_ip: str, dst_ip: str, **opts) -> None:
        self.verihl = (4 << 4) + 5  # Version + IHL
        self.dscp_ecn = (0 << 6) + 0  # DSCP + ECN
        self.total_length = opts.get("total_length", 0)
        self.id = opts.get("id", 0)
        self.flags = opts.get("flags", 0)
        self.fragment_offset = opts.get("fragment_offset", 0)
        self.flags_fragment_offset = (self.flags << 13) + self.fragment_offset
        self.ttl = opts.get("ttl", 64)
        self.protocol = protocol
        self.checksum = opts.get("checksum", 0)
        self.src_ip = inet_aton(src_ip)
        self.dst_ip = inet_aton(dst_ip)

    def set_length(self, payload_length: int) -> None:
        self.total_length = 20 + payload_length  # IP header + payload

    def get_total_length(self) -> int:
        return self.total_length

    def get_payload_length(self) -> int:
        return self.total_length - 20

    def has_checksum(self) -> bool:
        return False  # the checksum of the IP layer is calculated by the kernel

    def serialize(self, buf: io.BytesIO) -> None:
        buf.write(
            struct.pack(
                "!BBHHHBBH4s4s",
                self.verihl,
                self.dscp_ecn,
                self.total_length,
                self.id,
                self.flags_fragment_offset,
                self.ttl,
                self.protocol,
                self.checksum,
                self.src_ip,
                self.dst_ip,
            )
        )


class UDPLayer(Layer):
    def __init__(self, src_port, dst_port, **opts) -> None:
        self.src_port = src_port
        self.dst_port = dst_port
        self.length = opts.get("length", 0)
        self.checksum = opts.get("checksum", 0)

    def set_length(self, payload_length: int) -> None:
        self.length = 8 + payload_length  # UDP Header + payload

    def get_total_length(self) -> int:
        return self.length

    def get_payload_length(self) -> int:
        return self.length - 8

    def has_checksum(self) -> bool:
        return True

    def serialize(self, buf: io.BytesIO) -> None:
        buf.write(
            struct.pack(
                "!HHHH", self.src_port, self.dst_port, self.length, self.checksum
            )
        )


class Payload(Layer):
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def set_length(self, payload_length: int) -> None:
        pass

    def get_total_length(self) -> int:
        return len(self.payload)

    def get_payload_length(self) -> int:
        return len(self.payload)

    def has_checksum(self) -> bool:
        return False

    def serialize(self, buf: io.BytesIO) -> None:
        buf.write(self.payload)


def serialize_layers(*layers: Layer) -> bytes:
    first_time = True
    curr_payload: int
    for layer in reversed(layers):
        if first_time:
            curr_payload = layer.get_total_length()
            first_time = False
        else:
            layer.set_length(curr_payload)
            curr_payload = layer.get_total_length()
    buf = io.BytesIO()
    for layer in layers:
        layer.serialize(buf)
    buf.flush()
    res = buf.getvalue()
    buf.close()
    return res
