"""Representations of the higher-level protocol structures, such as options and packets.

This module doesn't include any transaction logic; it only represents the structures themselves.
"""

# To help ensure compatibility between Python 2.7 and Python 3, import these modules.
# See the Google Python Style Guide section 2.20:
# https://google.github.io/styleguide/pyguide.html#220-modern-python-python-3-and-from-__future__-imports
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from . import primitives


def _generate_repr(cls, *args, **kwargs):
    """Generates a good-looking response to repr() and reduces repeated formatting boilerplate.
    """
    params = ["{!r}".format(arg) for arg in args]
    params += ["{}={!r}".format(key, val) for key, val in kwargs.items()]
    return "{}.{}({})".format(cls.__module__, cls.__name__, ", ".join(params))


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
        return primitives.encode_str(self.name) + primitives.encode_str(self.value)

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
        name, next_offset = primitives.decode_str(byte_arr, offset)
        value, next_offset = primitives.decode_str(byte_arr, next_offset)
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
            packet_type = primitives.PacketType.WRQ
        else:
            packet_type = primitives.PacketType.RRQ

        packet = []
        packet.append(primitives.PacketType.encode(packet_type))
        packet.append(primitives.encode_str(self.filename))
        packet.append(primitives.TransferMode.encode(self.mode))

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
        decoded_type, next_offset = primitives.PacketType.decode(byte_arr, offset)
        if decoded_type == primitives.PacketType.WRQ:
            is_write = True
        elif decoded_type == primitives.PacketType.RRQ:
            is_write = False
        else:
            # TODO: Should we make a custom exception type? Is TypeError better here?
            raise ValueError("Not a request packet.", decoded_type, byte_arr, offset)

        decoded_filename, next_offset = primitives.decode_str(byte_arr, next_offset)
        decoded_mode, next_offset = primitives.TransferMode.decode(byte_arr, next_offset)

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
        packet.append(primitives.PacketType.encode(primitives.PacketType.ERROR))
        packet.append(primitives.ErrorCode.encode(self.code))
        packet.append(primitives.encode_str(self.message))
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
        decoded_type, next_offset = primitives.PacketType.decode(byte_arr, offset)
        if decoded_type != primitives.PacketType.ERROR:
            # TODO: Should we make a custom exception type? Is TypeError better here?
            raise ValueError("Not an error packet.", decoded_type, byte_arr, offset)

        decoded_code, next_offset = primitives.ErrorCode.decode(byte_arr, next_offset)
        decoded_msg, next_offset = primitives.decode_str(byte_arr, next_offset)

        return ErrorPacket(decoded_code, decoded_msg), next_offset


class DataPacket(object):
    """Representation of a data packet.

    This class does not attempt to manage any kind of session logic, such as block size or
    transaction termination. It is simply a plain representation of the packet itself.

    Attributes:
        block_num (int): The block number of this data packet.
        data (bytes): The byte data of this packet. When creating and consuming these packets, make
            sure to respect the transfer mode. That is, if the transfer mode is NETASCII, you
            should encode your content as ASCII before writing to this attribute and decode them
            when reading from it; if the transfer mode is OCTET, you don't need to encode or decode.
    """

    def __init__(self, block_num, data):
        """Creates a DataPacket from Python values.

        See also: DataPacket.decode(), for parsing from a byte array.

        Attributes:
            block_num (int): The block number of this data packet.
            data (bytes): The byte data of this packet. Make sure to respect the transfer mode of
                the current operation. That is, if the transfer mode is NETASCII, you should encode
                your content as ASCII before providing it to this constructor; if the transfer mode
                is OCTET, you don't need to encode your content.
        """
        self.block_num = block_num
        self.data = data

    def __repr__(self):
        """Returns a succinct representation of this DataPacket as a string.

        Returns:
            str: Accurate and succinct description of this DataPacket.
        """
        return _generate_repr(self.__class__, block_num=self.block_num, data=self.data)

    def encode(self):
        """Encodes the DataPacket into a byte array to send it over the network.

        Returns:
            bytes: A byte array encoding the data packet.

        Raises:
            ValueError: If the block number is zero.
            struct.error: If the block number is not a valid uint16.
            TypeError: If the data is not a bytes-like object.
        """
        if self.block_num == 0:
            raise ValueError("Data block numbers start at one, not zero!")
        packet = []
        packet.append(primitives.PacketType.encode(primitives.PacketType.DATA))
        packet.append(primitives.encode_uint16(self.block_num))
        packet.append(self.data)
        return b"".join(packet)

    @staticmethod
    def decode(byte_arr, offset=0):
        """Decodes a DataPacket from a byte array received from the network.

        Args:
            byte_arr (bytes): The byte array to decode.
            offset (int): The offset into the byte array to start decoding. Defaults to 0.

        Returns:
            DataPacket: The decoded packet.

        Raises:
            ValueError: If the packet given has the wrong type (i.e. not DATA) or if the decoded
                block number is zero (which is invalid for DATA packets).
            PacketType.UnknownPacketTypeError: If the packet has an unrecognized type.
            struct.error: If the packet didn't include enough bytes for the packet type and block
            number fields.
        """
        decoded_type, next_offset = primitives.PacketType.decode(byte_arr, offset)
        if decoded_type != primitives.PacketType.DATA:
            # TODO: Should we make a custom exception type? Is TypeError better here?
            raise ValueError("Not a data packet.", decoded_type, byte_arr, offset)

        decoded_block_num, next_offset = primitives.decode_uint16(byte_arr, next_offset)
        if decoded_block_num == 0:
            raise ValueError("Data block numbers start at one, not zero!")

        decoded_data = byte_arr[next_offset:]
        next_offset = len(byte_arr)

        return DataPacket(decoded_block_num, decoded_data), next_offset


class AckPacket(object):
    """Representation of an ACK packet.

    OACK packets, as introduced by RFC 2347, are represented by the OackPacket class.

    Attributes:
        block_num (int): The block number being acknowledged (or 0 if acknowledging a WRQ or OACK).
    """

    def __init__(self, block_num):
        """Creates an AckPacket from Python values.

        See also: AckPacket.decode(), for parsing from a byte array.

        Args:
            block_num (int): The block number being acknowledged (or 0 if acknowledging a WRQ or
                OACK).
        """
        self.block_num = block_num

    def __repr__(self):
        """Returns a succinct representation of this AckPacket as a string.

        Returns:
            str: Accurate and succinct description of this AckPacket.
        """
        return _generate_repr(self.__class__, block_num=self.block_num)

    def encode(self):
        """Encodes the AckPacket into a byte array to send it over the network.

        Returns:
            bytes: A byte array encoding the ACK packet.

        Raises:
            struct.error: If the block number is not a valid uint16.
        """
        packet = []
        packet.append(primitives.PacketType.encode(primitives.PacketType.ACK))
        packet.append(primitives.encode_uint16(self.block_num))
        return b"".join(packet)

    @staticmethod
    def decode(byte_arr, offset=0):
        """Decodes an AckPacket from a byte array received from the network.

        Args:
            byte_arr (bytes): The byte array to decode.
            offset (int): The offset into the byte array to start decoding. Defaults to 0.

        Returns:
            AckPacket: The decoded packet.

        Raises:
            ValueError: If the packet given has the wrong type (i.e. not ACK).
            PacketType.UnknownPacketTypeError: If the packet has an unrecognized type.
            struct.error: If the packet didn't include enough bytes for the packet type and block
                number fields.
        """
        decoded_type, next_offset = primitives.PacketType.decode(byte_arr, offset)
        if decoded_type != primitives.PacketType.ACK:
            # TODO: Should we make a custom exception type? Is TypeError better here?
            raise ValueError("Not an ACK packet.", decoded_type, byte_arr, offset)

        decoded_block_num, next_offset = primitives.decode_uint16(byte_arr, next_offset)
        return AckPacket(decoded_block_num), next_offset


class OackPacket(object):
    """Representation of an OACK packet.

    OACK packets were introduced by RFC 2347, and are slightly different from ACK packets.

    Attributes:
        options (dict(str, str)): The TFTP options to include in the OACK.
    """

    def __init__(self, options):
        """Creates an OackPacket from Python values.

        See also: OackPacket.decode(), for parsing from a byte array.

        Args:
            options (dict(str, str)): The TFTP options to include in the OACK.
        """
        self.options = options

    def __repr__(self):
        """Returns a succinct representation of this OackPacket as a string.

        Returns:
            str: Accurate and succinct description of this OackPacket.
        """
        return _generate_repr(self.__class__, options=self.options)

    def encode(self):
        """Encodes the OackPacket into a byte array to send it over the network.

        Returns:
            bytes: A byte array encoding the OACK packet.
        """
        packet = []
        packet.append(primitives.PacketType.encode(primitives.PacketType.OACK))
        packet.extend([Option(name, value).encode() for name, value in self.options.items()])
        return b"".join(packet)

    @staticmethod
    def decode(byte_arr, offset=0):
        """Decodes an OackPacket from a byte array received from the network.

        Args:
            byte_arr (bytes): The byte array to decode.
            offset (int): The offset into the byte array to start decoding. Defaults to 0.

        Returns:
            OackPacket: The decoded packet.

        Raises:
            ValueError: If the packet given has the wrong type (i.e. not OACK).
            PacketType.UnknownPacketTypeError: If the packet has an unrecognized type.
            NullTerminatorNotFoundError: If the packet included an incomplete option (i.e. name,
                but no value).
            struct.error: If the packet didn't include enough bytes for the packet type field.
        """
        decoded_type, next_offset = primitives.PacketType.decode(byte_arr, offset)
        if decoded_type != primitives.PacketType.OACK:
            # TODO: Should we make a custom exception type? Is TypeError better here?
            raise ValueError("Not an OACK packet.", decoded_type, byte_arr, offset)

        decoded_options = {}
        while next_offset != len(byte_arr):
            option, next_offset = Option.decode(byte_arr, next_offset)
            decoded_options[option.name] = option.value

        return OackPacket(decoded_options)
