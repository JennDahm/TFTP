"""Representations of the different packet types, constants, and functions to translate to and from
byte streams.
"""

# To help ensure compatibility between Python 2.7 and Python 3, import these modules.
# See the Google Python Style Guide section 2.20:
# https://google.github.io/styleguide/pyguide.html#220-modern-python-python-3-and-from-__future__-imports
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from future.utils import raise_from
import struct

import constantly


def _generate_repr(cls, *args, **kwargs):
    """Generates a good-looking response to repr() and reduces repeated formatting boilerplate.
    """
    params = ["{!r}".format(arg) for arg in args]
    params += ["{}={!r}".format(key, val) for key, val in kwargs.items()]
    return "{}.{}({})".format(cls.__module__, cls.__name__, ", ".join(params))


def encode_str(s):
    """Encodes the given string as a null-terminated ASCII byte array.

    Args:
        s (str): The ASCII string to encode. Must not contain null characters.

    Returns:
        bytes: A byte array encoding the string, terminated with a null character.

    Raises:
        ValueError: If the given string contains a null character or is invalid ASCII.
    """
    if "\x00" in s:
        raise ValueError("Encoded string cannot contain null characters.", s)
    encoded_s = s.encode("ascii")
    return struct.pack(">{}sx".format(len(encoded_s)), encoded_s)


def decode_str(byte_arr, offset=0):
    """Decodes a null-terminated ASCII string from the given byte array.

    Args:
        byte_arr (bytes): The byte array to decode.
        offset (int): The offset into the byte array to start decoding. Defaults to 0.

    Returns:
        (str, int): A tuple of the string decoded from the byte array and the offset of the first
            byte following the encoded string.

    Raises:
        ValueError: If the encoded string is invalid ASCII.
        NullTerminatorNotFoundError: If there wasn't a null-terminator to bound the encoded string.
    """
    index_of_term = byte_arr.find(b"\x00", offset)
    if index_of_term < 0:
        raise NullTerminatorNotFoundError(byte_arr, offset)
    return (byte_arr[offset:index_of_term].decode(encoding="ascii"), index_of_term + 1)


class NullTerminatorNotFoundError(ValueError):
    """Thrown when decoding a string when a null terminator isn't found.

    Attributes:
        byte_arr (bytes): The byte array we were attempting to decode.
        offset (int): The offset we started decoding from.
    """

    def __init__(self, byte_arr, offset):
        """Creates a NullTerminatorNotFoundError.

        Args:
            byte_arr (bytes): The byte array we were attempting to decode.
            offset (int): The offset we started decoding from.
        """
        self.byte_arr = byte_arr
        self.offset = offset


def encode_uint16(s):
    """Encodes the given uint16 as a big-endian byte array.

    Args:
        s (int): The unsigned 16-bit integer to encode.

    Returns:
        bytes: A byte array encoding the uint16.

    Raises:
        struct.error: If the given integer is not within [0, 65535]
    """
    return struct.pack(">H", s)


def decode_uint16(byte_arr, offset=0):
    """Decodes a uint16 from the given byte array.

    Args:
        byte_arr (bytes): The byte array to decode.
        offset (int): The offset into the byte array to start decoding. Defaults to 0.

    Returns:
        (int, int): A tuple of the uint16 decoded from the byte array and the offset of the first
            byte following the encoded uint16.

    Raises:
        struct.error: If there are not at least two bytes left in the byte array starting at offset.
    """
    s, = struct.unpack_from(">H", byte_arr, offset)
    return s, offset + 2


class PacketType(constantly.Values):
    """Representation of the different packet types.

    The various packet types are defined in RFC 1350. RFC 2347 adds an additional packet type:
    OACK (6)
    """
    RRQ = constantly.ValueConstant(1)
    WRQ = constantly.ValueConstant(2)
    DATA = constantly.ValueConstant(3)
    ACK = constantly.ValueConstant(4)
    ERROR = constantly.ValueConstant(5)
    OACK = constantly.ValueConstant(6)

    @classmethod
    def encode(cls, packet_type):
        """Encodes the packet type into a byte array to construct packets with.

        Args:
            packet_type (PacketType): The packet type to encode.

        Returns:
            bytes: The packet type encoded as a byte array.
        """
        return encode_uint16(packet_type.value)

    @classmethod
    def decode(cls, byte_arr, offset=0):
        """Decodes a packet type from a byte array.

        Args:
            byte_arr (bytes): The byte array to decode.
            offset (int): The offset into the byte array to start decoding. Defaults to 0.

        Returns:
            (PacketType, int): A tuple of the decoded packet type and the offset of the first byte
                following the encoded packet type.

        Raises:
            PacketType.UnknownPacketTypeError: If we don't recognize the decoded packet type.
            struct.error: If there weren't enough bytes left in the byte array to decode a packet
                type.
        """
        code, next_offset = decode_uint16(byte_arr, offset)
        try:
            return (cls.lookupByValue(code), next_offset)
        except ValueError:
            raise_from(cls.UnknownPacketTypeError(code, byte_arr, offset), None)

    class UnknownPacketTypeError(ValueError):
        """Thrown when we receive a packet with an unrecognized packet type.

        Attributes:
            code (int): The packet's opcode.
            byte_arr (bytes): The byte array we attempted to decode.
            offset (int): The offset we started decoding from.
        """

        def __init__(self, code, byte_arr, offset):
            """Creates an UnknownPacketTypeError.

            Args:
                code (int): The packet's opcode.
                byte_arr (bytes): The byte array we attempted to decode.
                offset (int): The offset we started decoding from.
            """
            self.code = code
            self.byte_arr = byte_arr
            self.offset = offset


class TransferMode(constantly.Values):
    """Representation of the different transfer modes. Also includes some convenient aliases.

    The various transfer modes are defined in RFC 1350.
    """
    NETASCII = constantly.ValueConstant("netascii")
    OCTET = constantly.ValueConstant("octet")
    MAIL = constantly.ValueConstant("mail")
    ASCII = constantly.ValueConstant("netascii")
    TEXT = constantly.ValueConstant("netascii")
    BINARY = constantly.ValueConstant("octet")

    @classmethod
    def encode(cls, mode):
        """Encodes the transfer mode into a byte array to construct packets with.

        Args:
            mode (TransferMode): The transfer mode to encode.

        Returns:
            bytes: The transfer mode encoded as a byte array.
        """
        return encode_str(mode.value)

    @classmethod
    def decode(cls, byte_arr, offset=0):
        """Decodes the transfer mode from the given byte array.

        Args:
            byte_arr (bytes): The byte array to decode.
            offset (int): The offset into the byte array to start decoding. Defaults to 0.

        Returns:
            (TransferMode, int): A tuple of the decoded transfer mode and the offset of the first
                byte following the encoded transfer mode.

        Raises:
            ValueError: If the encoded string is invalid ASCII.
            NullTerminatorNotFoundError: If there wasn't a transfer mode string to decode or if
                there wasn't a null-terminator to bound the encoded string.
            TransferMode.UnknownTransferModeError: If we don't recognize the encoded transfer mode.
        """
        decoded_mode, next_offset = decode_str(byte_arr, offset)
        try:
            return (cls.lookupByValue(decoded_mode), next_offset)
        except ValueError:
            raise_from(cls.UnknownTransferModeError(decoded_mode, byte_arr, offset), None)

    class UnknownTransferModeError(ValueError):
        """Thrown when we receive a packet with an unrecognized transfer mode.

        Attributes:
            mode (int): The decoded transfer mode.
            byte_arr (bytes): The byte array we attempted to decode.
            offset (int): The offset we started decoding from.
        """

        def __init__(self, mode, byte_arr, offset):
            """Creates an UnknownTransferModeError.

            Args:
                mode (int): The packet's transfer mode.
                byte_arr (bytes): The byte array we attempted to decode.
                offset (int): The offset we started decoding from.
            """
            self.mode = mode
            self.byte_arr = byte_arr
            self.offset = offset


class ErrorCode(constantly.Values):
    """Represents a TFTP error code.

    The various error codes are defined in RFC 1350. RFC 2347 adds an additional error code:
    OPTION_FAILURE (8).
    """
    CUSTOM = constantly.ValueConstant(0)
    FILE_NOT_FOUND = constantly.ValueConstant(1)
    ACCESS_VIOLATION = constantly.ValueConstant(2)
    DISK_FULL = constantly.ValueConstant(3)
    ILLEGAL_OP = constantly.ValueConstant(4)
    UNKNOWN_ID = constantly.ValueConstant(5)
    FILE_EXISTS = constantly.ValueConstant(6)
    NO_SUCH_USER = constantly.ValueConstant(7)
    OPTION_FAILURE = constantly.ValueConstant(8)
    # Note that, unfortunately, there's no way to provide a "catchall constant", which means that
    # unrecognized error codes will cause an exception. I don't know the best way to address this.

    @classmethod
    def encode(cls, error_code):
        """Encodes the error code into a byte array to construct packets with.

        Args:
            error_code (ErrorCode): The error code to encode.

        Returns:
            bytes: The error code encoded as a byte array.
        """
        return encode_uint16(error_code.value)

    @classmethod
    def decode(cls, byte_arr, offset=0):
        """Decodes a error code from a byte array.

        Args:
            byte_arr (bytes): The byte array to decode.
            offset (int): The offset into the byte array to start decoding. Defaults to 0.

        Returns:
            (ErrorCode, int): A tuple of the error code type and the offset of the first byte
                following the encoded error code.

        Raises:
            ErrorCode.UnknownErrorCodeError: If we don't recognize the decoded error code.
            struct.error: If there weren't enough bytes left in the byte array to decode an error
                code.
        """
        code, next_offset = decode_uint16(byte_arr, offset)
        try:
            return (cls.lookupByValue(code), next_offset)
        except ValueError:
            raise_from(cls.UnknownErrorCodeError(code, byte_arr, offset), None)

    class UnknownErrorCodeError(ValueError):
        """Thrown when we receive a packet with an unrecognized error code.

        Attributes:
            code (int): The decoded error code.
            byte_arr (bytes): The byte array we attempted to decode.
            offset (int): The offset we started decoding from.
        """

        def __init__(self, code, byte_arr, offset):
            """Creates an UnknownErrorCodeError.

            Args:
                code (int): The packet's error code.
                byte_arr (bytes): The byte array we attempted to decode.
                offset (int): The offset we started decoding from.
            """
            self.code = code
            self.byte_arr = byte_arr
            self.offset = offset


class Option(object):
    """Represents a negotiable option in a TFTP transaction.

    Options are a backwards-compatible feature added to TFTP in RFC 2347. They are communicated as
    an ASCII option name paired with an ASCII option value. Standard options include:
    * "blksize" - The amount of file data in bytes to transfer in each DATA packet. Valid values
        are integers between 8 and 65464, inclusive. Defined in RFC 2348.
    * "timeout" - The timeout in seconds between retransmission attempts. Valid values are integers
        between 1 and 255, inclusive. Defined in RFC 2349.
    * "tsize" - The total size of the file to be transferred in bytes. Valid values are non-negative
        integers. Defined in RFC 2349.
    * "windowsize" - The number of data blocks to send between ACKs. Valid values are integers
        between 1 and 65535, inclusive. Proposed by RFC 7440.

    Attributes:
        name (str): ASCII option name.
        value (str): ASCII string representing the option value.
    """

    def __init__(self, name, value):
        """Creates an option with the given name and value.

        Attributes:
            name (str): ASCII option name.
            value (str): ASCII string representing the option value.
        """
        self.name = name
        self.value = value

    def __repr__(self):
        """Returns a succinct representation of this Option as a string.

        Returns:
            str: Accurate and succinct description of this Option.
        """
        return _generate_repr(self.__class__, self.name, self.value)

    def __eq__(self, other):
        """Compares two Options for equality in name and value.

        NotImplemented for types other than Option.

        Args:
            other (Option): The option to compare self to.

        Returns:
            bool: True if self and other have the same name and value; otherwise, False.
        """
        if not isinstance(other, Option):
            return NotImplemented
        return (self.name == other.name) and (self.value == other.value)

    def __ne__(self, other):
        """Compares two Options for inequality in name or value.

        NotImplemented for types other than Option.

        Args:
            other (Option): The option to compare self to.

        Returns:
            bool: True if self and other have the different names or values; otherwise, False.
        """
        eq = self.__eq__(other)
        return not eq if eq is not NotImplemented else NotImplemented

    def encode(self):
        """Encodes the option into a byte array to construct packets with.

        Returns:
            bytes: A byte array encoding the option.

        Raises:
            ValueError: If the option name or value contain null characters or are invalid ASCII.
        """
        return encode_str(self.name) + encode_str(self.value)

    @classmethod
    def decode(cls, byte_arr, offset=0):
        """Decodes an option from the given byte array.

        Args:
            byte_arr (bytes): The byte array to decode.
            offset (int): The offset into the byte array to start decoding. Defaults to 0.

        Returns:
            (Option, int): A tuple of the decoded option and the offset of the first byte following
                the encoded option.

        Raises:
            ValueError: If the encoded option contains invalid ASCII.
            NullTerminatorNotFoundError: If there were missing null terminators in the encoded
                option.
        """
        name, next_offset = decode_str(byte_arr, offset)
        value, next_offset = decode_str(byte_arr, next_offset)
        return Option(name, value), next_offset


class RequestPacket(object):
    """Representation of a WRQ or RRQ packet.

    The option negotiation format is described in RFC 2347.

    Attributes:
        is_write (bool): True if this is a WRQ; False if this is a RRQ.
        filename (str): ASCII string naming the file to read or write. Must not contain null
            characters.
        mode (TransferMode): The transfer mode (i.e. ascii vs binary).
        options (dict(str, str)): The TFTP options to include in the request.
    """

    def __init__(self, is_write, filename, mode, options=None):
        """Creates a RequestPacket from Python values.

        See also: RequestPacket.decode(), for parsing from a byte array.

        Args:
            is_write (bool): True if this is a WRQ; False if this is a RRQ.
            filename (str): ASCII string naming the file to read or write. Must not contain null
                characters.
            mode (TransferMode): The transfer mode (i.e. ascii vs binary).
            options (dict(str, str)): The TFTP options to include in the request. Default is None.
        """
        self.is_write = is_write
        self.filename = filename
        self.mode = mode
        if options:
            self.options = options
        else:
            self.options = {}

    def __repr__(self):
        """Returns a succinct representation of this RequestPacket as a string.

        Returns:
            str: Accurate and succinct description of this RequestPacket.
        """
        return _generate_repr(self.__class__,
                              is_write=self.is_write,
                              filename=self.filename,
                              mode=self.mode,
                              options=self.options)

    def encode(self):
        """Encodes the RequestPacket into a byte array to send it over the network.

        Returns:
            bytes: A byte array encoding the request packet.
        """
        if self.is_write:
            packet_type = PacketType.WRQ
        else:
            packet_type = PacketType.RRQ

        packet = []
        packet.append(PacketType.encode(packet_type))
        packet.append(encode_str(self.filename))
        packet.append(TransferMode.encode(self.mode))

        for name, value in self.options.items():
            packet.append(Option(name, value).encode())

        return b"".join(packet)

    @staticmethod
    def decode(byte_arr, offset=0):
        """Decodes a RequestPacket from a byte array received from the network.

        Args:
            byte_arr (bytes): The byte array to decode.
            offset (int): The offset into the byte array to start decoding. Defaults to 0.

        Returns:
            RequestPacket: The decoded packet.

        Raises:
            ValueError: If the packet given has the wrong type (i.e. not RRQ or WRQ).
            PacketType.UnknownPacketTypeError: If the packet has an unrecognized type.
            TransferMode.UnknownTransferModeError: If the packet has an unrecognized transfer mode.
            NullTerminatorNotFoundError: If the packet was missing a filename, missing a transfer
                mode, or included an incomplete option (i.e. name, but no value).
            struct.error: If the packet didn't include enough bytes for the packet type field.
        """
        decoded_type, next_offset = PacketType.decode(byte_arr, offset)
        if decoded_type == PacketType.WRQ:
            is_write = True
        elif decoded_type == PacketType.RRQ:
            is_write = False
        else:
            # TODO: Should we make a custom exception type? Is TypeError better here?
            raise ValueError("Not a request packet.", decoded_type, byte_arr, offset)

        decoded_filename, next_offset = decode_str(byte_arr, next_offset)
        decoded_mode, next_offset = TransferMode.decode(byte_arr, next_offset)

        decoded_options = {}
        while next_offset != len(byte_arr):
            option, next_offset = Option.decode(byte_arr, next_offset)
            decoded_options[option.name] = option.value

        return RequestPacket(is_write, decoded_filename, decoded_mode, decoded_options), next_offset


class ErrorPacket(object):
    """Representation of an error packet.

    Attributes:
        code (ErrorCode): The error code.
        message (str): ASCII error message. Must not contain null characters.
    """

    def __init__(self, code, message):
        """Creates a ErrorPacket from Python values.

        See also: ErrorPacket.decode(), for parsing from a byte array.

        Args:
            code (ErrorCode): The error code.
            message (str): ASCII error message. Must not contain null characters.
        """
        self.code = code
        self.message = message

    def __repr__(self):
        """Returns a succinct representation of this ErrorPacket as a string.

        Returns:
            str: Accurate and succinct description of this ErrorPacket.
        """
        return _generate_repr(self.__class__, code=self.code, message=self.message)

    def encode(self):
        """Encodes the ErrorPacket into a byte array to send it over the network.

        Returns:
            bytes: A byte array encoding the error packet.
        """
        packet = []
        packet.append(PacketType.encode(PacketType.ERROR))
        packet.append(ErrorCode.encode(self.code))
        packet.append(encode_str(self.message))
        return b"".join(packet)

    @staticmethod
    def decode(byte_arr, offset=0):
        """Decodes a ErrorPacket from a byte array received from the network.

        Args:
            byte_arr (bytes): The byte array to decode.
            offset (int): The offset into the byte array to start decoding. Defaults to 0.

        Returns:
            ErrorPacket: The decoded packet.

        Raises:
            ValueError: If the packet given has the wrong type (i.e. not ERROR).
            PacketType.UnknownPacketTypeError: If the packet has an unrecognized type.
            ErrorCode.UnknownErrorCodeError: If we don't recognize the decoded error code.
            NullTerminatorNotFoundError: If the packet was missing an error message.
            struct.error: If the packet didn't include enough bytes for the packet type and error
                code fields.
        """
        decoded_type, next_offset = PacketType.decode(byte_arr, offset)
        if decoded_type != PacketType.ERROR:
            # TODO: Should we make a custom exception type? Is TypeError better here?
            raise ValueError("Not an error packet.", decoded_type, byte_arr, offset)

        decoded_code, next_offset = ErrorCode.decode(byte_arr, next_offset)
        decoded_msg, next_offset = decode_str(byte_arr, next_offset)

        return ErrorPacket(decoded_code, decoded_msg), next_offset
