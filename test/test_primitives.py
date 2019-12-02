"""Tests the various primitives types in tftp.primitives
"""

# To help ensure compatibility between Python 2.7 and Python 3, import these modules.
# See the Google Python Style Guide section 2.20:
# https://google.github.io/styleguide/pyguide.html#220-modern-python-python-3-and-from-__future__-imports
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import pytest

from tftp import primitives


class TestStr(object):

    class TestEncode(object):
        NOMINAL_CASES = [
            ("hello world", b"hello world\x00"),
            ("", b"\x00"),
        ]

        @pytest.mark.parametrize("input_str,output_bytes", NOMINAL_CASES)
        def test_nominal(self, input_str, output_bytes):
            """Tests nominal uses of encode_str().
            """
            assert primitives.encode_str(input_str) == output_bytes

        NULL_CASES = [
            "oh\x00no",
            "at the end\x00",
            "\x00at the beginning",
            "\x00mult\x00iple\x00",
        ]

        @pytest.mark.parametrize("input_str", NULL_CASES)
        def test_null(self, input_str):
            """Tests cases where the input to encode_str() has a null character embedded in it.
            """
            with pytest.raises(ValueError):
                primitives.encode_str(input_str)

        BAD_ASCII_CASES = [
            u"an em dash\u2014quite dashing",
            "oh\x82bother",
        ]

        @pytest.mark.parametrize("input_str", BAD_ASCII_CASES)
        def test_bad_ascii(self, input_str):
            """Tests cases where the input to encode_str() is invalid ASCII.
            """
            with pytest.raises(ValueError):
                primitives.encode_str(input_str)

    class TestDecode(object):
        NOMINAL_CASES = [
            (b"hello world!\x00", 0, ("hello world!", 13)),
            (b"hello world!\x00", 2, ("llo world!", 13)),
            (b"hello world!\x00", 12, ("", 13)),
            (b"file\x00octet\x00", 0, ("file", 5)),
            (b"file\x00octet\x00", 5, ("octet", 11)),
        ]

        @pytest.mark.parametrize("input_bytes,offset,exp_output", NOMINAL_CASES)
        def test_nominal(self, input_bytes, offset, exp_output):
            """Tests nominal uses of primitives.decode_str().
            """
            assert primitives.decode_str(input_bytes, offset) == exp_output

        NO_NULL_CASES = [
            (b"hello world!", 0),
            (b"file\x00octet", 5),
        ]

        @pytest.mark.parametrize("input_bytes,offset", NO_NULL_CASES)
        def test_no_null(self, input_bytes, offset):
            """Test cases where the input to decode is missing a null terminator.
            """
            with pytest.raises(primitives.NullTerminatorNotFoundError):
                primitives.decode_str(input_bytes, offset)

        BAD_ASCII_CASES = [
            u"an em dash\u2014quite dashing".encode("utf-8"),
            b"oh\x82bother",
        ]

        @pytest.mark.parametrize("input_bytes", BAD_ASCII_CASES)
        def test_bad_ascii(self, input_bytes):
            """Tests cases where the input to decode_str() is invalid ASCII.
            """
            with pytest.raises(ValueError):
                primitives.decode_str(input_bytes, 0)

    def test_endtoend(self):
        """Tests string encoding end-to-end.
        """
        assert primitives.decode_str(primitives.encode_str("hello")) == ("hello", 6)


class TestUint16(object):

    class TestEncode(object):
        NOMINAL_CASES = [
            (44, b"\x00\x2c"),
            (0, b"\x00\x00"),
            (65535, b"\xff\xff"),
            (3356, b"\x0d\x1c"),
        ]

        @pytest.mark.parametrize("value,exp_output", NOMINAL_CASES)
        def test_nominal(self, value, exp_output):
            """Tests nominal encoding of uint16s.
            """
            assert primitives.encode_uint16(value) == exp_output

        BAD_VALUE_CASES = [
            (-20, primitives.struct.error),
            (66666, primitives.struct.error),
        ]

        @pytest.mark.parametrize("value,exp_error", BAD_VALUE_CASES)
        def test_bad_values(self, value, exp_error):
            """Tests encode_uint16() when given an integer that isn't a uint16.
            """
            with pytest.raises(exp_error):
                primitives.encode_uint16(value)

    class TestDecode(object):
        NOMINAL_CASES = [
            (b"\x00\x2c", 0, 44),
            (b"\x00\x00", 0, 0),
            (b"\xff\xff", 0, 65535),
            (b"\x0d\x1c", 0, 3356),
            (b"\x0d\x1c\x01", 1, 7169),
        ]

        @pytest.mark.parametrize("byte_arr,offset,exp_output", NOMINAL_CASES)
        def test_nominal(self, byte_arr, offset, exp_output):
            """Tests nominal decoding of uint16s.
            """
            assert primitives.decode_uint16(byte_arr, offset) == (exp_output, offset + 2)

    @pytest.mark.parametrize("value", [23, 6603, 0, 0xFFFF])
    def test_endtoend(self, value):
        """Tests uint16 encoding end-to-end
        """
        assert primitives.decode_uint16(primitives.encode_uint16(value)) == (value, 2)


class TestPacketType(object):

    class TestEncode(object):
        NOMINAL_CASES = [
            (primitives.PacketType.RRQ, b"\x00\x01"),
            (primitives.PacketType.WRQ, b"\x00\x02"),
            (primitives.PacketType.DATA, b"\x00\x03"),
            (primitives.PacketType.ACK, b"\x00\x04"),
            (primitives.PacketType.ERROR, b"\x00\x05"),
            (primitives.PacketType.OACK, b"\x00\x06"),
        ]

        @pytest.mark.parametrize("input_type,exp_output", NOMINAL_CASES)
        def test_nominal(self, input_type, exp_output):
            """Tests nominal uses of PacketType.encode()
            """
            assert primitives.PacketType.encode(input_type) == exp_output

    class TestDecode(object):
        NOMINAL_CASES = [
            (b"\x00\x01", 0, primitives.PacketType.RRQ),
            (b"\x00\x02", 0, primitives.PacketType.WRQ),
            (b"\x00\x03", 0, primitives.PacketType.DATA),
            (b"\x00\x04", 0, primitives.PacketType.ACK),
            (b"\x00\x05", 0, primitives.PacketType.ERROR),
            (b"\x00\x06", 0, primitives.PacketType.OACK),
            (b"\xaf\x00\x06", 1, primitives.PacketType.OACK),
            (b"\x00\x01\x00\x02", 2, primitives.PacketType.WRQ),
            (b"\x00\x01\x00\x02", 0, primitives.PacketType.RRQ),
        ]

        @pytest.mark.parametrize("input_bytes,offset,exp_output", NOMINAL_CASES)
        def test_nominal(self, input_bytes, offset, exp_output):
            """Tests nominal uses of PacketType.decode()
            """
            assert primitives.PacketType.decode(input_bytes, offset) == (exp_output, offset + 2)

        UNKNOWN_TYPE_CASES = [
            b"\x00\x00",
            b"\x00\x07",
            b"\x00\x08",
            b"\x00\x09",
            b"\x00\x20",
            b"\x01\x00",
            b"\xFF\xFF",
        ]

        @pytest.mark.parametrize("input_bytes", UNKNOWN_TYPE_CASES)
        def test_unknown_type(self, input_bytes):
            """Tests parsing of unknown types.
            """
            with pytest.raises(primitives.PacketType.UnknownPacketTypeError):
                primitives.PacketType.decode(input_bytes, 0)

    @pytest.mark.parametrize("packet_type", [
        primitives.PacketType.RRQ,
        primitives.PacketType.WRQ,
        primitives.PacketType.DATA,
        primitives.PacketType.ACK,
        primitives.PacketType.ERROR,
        primitives.PacketType.OACK,
    ])
    def test_endtoend(self, packet_type):
        """Tests end-to-end encoding and decoding of packet types.
        """
        assert primitives.PacketType.decode(
            primitives.PacketType.encode(packet_type)) == (packet_type, 2)


class TestTransferMode(object):

    class TestEncode(object):
        NOMINAL_CASES = [
            (primitives.TransferMode.NETASCII, b"netascii\0"),
            (primitives.TransferMode.OCTET, b"octet\0"),
            (primitives.TransferMode.MAIL, b"mail\0"),
            (primitives.TransferMode.ASCII, b"netascii\0"),
            (primitives.TransferMode.TEXT, b"netascii\0"),
            (primitives.TransferMode.BINARY, b"octet\0"),
        ]

        @pytest.mark.parametrize("transfer_mode,exp_output", NOMINAL_CASES)
        def test_nominal(self, transfer_mode, exp_output):
            """Tests nominal uses of TransferMode.encode().
            """
            assert primitives.TransferMode.encode(transfer_mode) == exp_output

    class TestDecode(object):
        NOMINAL_CASES = [
            (b"netascii\0", 0, (primitives.TransferMode.NETASCII, 9)),
            (b"octet\0", 0, (primitives.TransferMode.OCTET, 6)),
            (b"mail\0", 0, (primitives.TransferMode.MAIL, 5)),
            (b"mail\0netascii\0", 0, (primitives.TransferMode.MAIL, 5)),
            (b"mail\0netascii\0", 5, (primitives.TransferMode.NETASCII, 14)),
        ]

        @pytest.mark.parametrize("input_bytes,offset,exp_output", NOMINAL_CASES)
        def test_nominal(self, input_bytes, offset, exp_output):
            """Tests nominal uses of PacketType.decode()
            """
            assert primitives.TransferMode.decode(input_bytes, offset) == exp_output

        UNKNOWN_TYPE_CASES = [
            (b"ascii\0", 0),  # The TFTP spec doesn't allow 'ascii' as an alias of 'netascii'.
            (b"text\0", 0),  # The TFTP spec doesn't allow 'text' as an alias of 'netascii'.
            (b"binary\0", 0),  # The TFTP spec doesn't allow 'binary' as an alias of 'octet'.
            (b"email\0", 0),  # The TFTP spec doesn't allow 'email' as an alias of 'mail.
            (b"netascii\0", 2),
            (b"sldjf\0", 0),
            (b"\0", 0),
        ]

        @pytest.mark.parametrize("input_bytes,offset", UNKNOWN_TYPE_CASES)
        def test_unknown_type(self, input_bytes, offset):
            """Tests parsing unknown transfer modes.
            """
            with pytest.raises(primitives.TransferMode.UnknownTransferModeError):
                primitives.TransferMode.decode(input_bytes, offset)

    @pytest.mark.parametrize(
        "transfer_mode,exp_output",
        [
            (primitives.TransferMode.NETASCII, (primitives.TransferMode.NETASCII, 9)),
            (primitives.TransferMode.OCTET, (primitives.TransferMode.OCTET, 6)),
            (primitives.TransferMode.MAIL, (primitives.TransferMode.MAIL, 5)),
            # Unfortunately, constantly doesn't have good support for aliases, and so ASCII !=
            # NETASCII (etc.) even if that's my intention.
            (primitives.TransferMode.ASCII, (primitives.TransferMode.NETASCII, 9)),
            (primitives.TransferMode.TEXT, (primitives.TransferMode.NETASCII, 9)),
            (primitives.TransferMode.BINARY, (primitives.TransferMode.OCTET, 6)),
        ])
    def test_endtoend(self, transfer_mode, exp_output):
        """Tests end-to-end encoding and decoding of transfer mode.
        """
        assert primitives.TransferMode.decode(
            primitives.TransferMode.encode(transfer_mode)) == exp_output


class TestErrorCode(object):

    class TestEncode(object):
        NOMINAL_CASES = [
            (primitives.ErrorCode.CUSTOM, b"\x00\x00"),
            (primitives.ErrorCode.FILE_NOT_FOUND, b"\x00\x01"),
            (primitives.ErrorCode.ACCESS_VIOLATION, b"\x00\x02"),
            (primitives.ErrorCode.DISK_FULL, b"\x00\x03"),
            (primitives.ErrorCode.ILLEGAL_OP, b"\x00\x04"),
            (primitives.ErrorCode.UNKNOWN_ID, b"\x00\x05"),
            (primitives.ErrorCode.FILE_EXISTS, b"\x00\x06"),
            (primitives.ErrorCode.NO_SUCH_USER, b"\x00\x07"),
            (primitives.ErrorCode.OPTION_FAILURE, b"\x00\x08"),
        ]

        @pytest.mark.parametrize("error_code,exp_output", NOMINAL_CASES)
        def test_nominal(self, error_code, exp_output):
            """Tests nominal uses of ErrorCode.encode()
            """
            assert primitives.ErrorCode.encode(error_code) == exp_output

    class TestDecode(object):
        NOMINAL_CASES = [
            (b"\x00\x00", 0, primitives.ErrorCode.CUSTOM),
            (b"\x00\x01", 0, primitives.ErrorCode.FILE_NOT_FOUND),
            (b"\x00\x02", 0, primitives.ErrorCode.ACCESS_VIOLATION),
            (b"\x00\x03", 0, primitives.ErrorCode.DISK_FULL),
            (b"\x00\x04", 0, primitives.ErrorCode.ILLEGAL_OP),
            (b"\x00\x05", 0, primitives.ErrorCode.UNKNOWN_ID),
            (b"\x00\x06", 0, primitives.ErrorCode.FILE_EXISTS),
            (b"\x00\x07", 0, primitives.ErrorCode.NO_SUCH_USER),
            (b"\x00\x08", 0, primitives.ErrorCode.OPTION_FAILURE),
            (b"\xe0\x00\x05", 1, primitives.ErrorCode.UNKNOWN_ID),
            (b"\x00\x00\x00\x01", 0, primitives.ErrorCode.CUSTOM),
            (b"\x00\x00\x00\x01", 2, primitives.ErrorCode.FILE_NOT_FOUND),
        ]

        @pytest.mark.parametrize("input_bytes,offset,exp_output", NOMINAL_CASES)
        def test_nominal(self, input_bytes, offset, exp_output):
            """Tests nominal uses of PacketType.decode()
            """
            assert primitives.ErrorCode.decode(input_bytes, offset) == (exp_output, offset + 2)

        UNKNOWN_ERROR_CODES_CASES = [
            b"\x00\x09",
            b"\x00\x0a",
            b"\x00\x0b",
            b"\x00\x0c",
            b"\x00\x20",
            b"\x01\x00",
            b"\xFF\xFF",
        ]

        @pytest.mark.parametrize("input_bytes", UNKNOWN_ERROR_CODES_CASES)
        def test_unknown_error_code(self, input_bytes):
            """Tests parsing of unknown error codes.
            """
            with pytest.raises(primitives.ErrorCode.UnknownErrorCodeError):
                primitives.ErrorCode.decode(input_bytes, 0)

    @pytest.mark.parametrize("error_code", [
        primitives.ErrorCode.CUSTOM,
        primitives.ErrorCode.FILE_NOT_FOUND,
        primitives.ErrorCode.ACCESS_VIOLATION,
        primitives.ErrorCode.DISK_FULL,
        primitives.ErrorCode.ILLEGAL_OP,
        primitives.ErrorCode.UNKNOWN_ID,
        primitives.ErrorCode.FILE_EXISTS,
        primitives.ErrorCode.NO_SUCH_USER,
        primitives.ErrorCode.OPTION_FAILURE,
    ])
    def test_endtoend(self, error_code):
        """Tests end-to-end encoding and decoding of error codes.
        """
        assert primitives.ErrorCode.decode(primitives.ErrorCode.encode(error_code)) == (error_code,
                                                                                        2)
