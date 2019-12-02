"""Representations of the most primitive data types expressed in the TFTP protocol.

Specifically, this includes null-terminated byte strings, uint16s, and enum representations of
packet type, error code, and transfer mode.
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
