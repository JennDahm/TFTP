"""Tests the various protocol types in tftp.protocol
"""

# To help ensure compatibility between Python 2.7 and Python 3, import these modules.
# See the Google Python Style Guide section 2.20:
# https://google.github.io/styleguide/pyguide.html#220-modern-python-python-3-and-from-__future__-imports
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from collections import OrderedDict

import pytest

from tftp import protocol


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
            assert protocol.encode_str(input_str) == output_bytes

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
                protocol.encode_str(input_str)

        BAD_ASCII_CASES = [
            u"an em dash\u2014quite dashing",
            "oh\x82bother",
        ]

        @pytest.mark.parametrize("input_str", BAD_ASCII_CASES)
        def test_bad_ascii(self, input_str):
            """Tests cases where the input to encode_str() is invalid ASCII.
            """
            with pytest.raises(ValueError):
                protocol.encode_str(input_str)

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
            """Tests nominal uses of protocol.decode_str().
            """
            assert protocol.decode_str(input_bytes, offset) == exp_output

        NO_NULL_CASES = [
            (b"hello world!", 0),
            (b"file\x00octet", 5),
        ]

        @pytest.mark.parametrize("input_bytes,offset", NO_NULL_CASES)
        def test_no_null(self, input_bytes, offset):
            """Test cases where the input to decode is missing a null terminator.
            """
            with pytest.raises(protocol.NullTerminatorNotFoundError):
                protocol.decode_str(input_bytes, offset)

        BAD_ASCII_CASES = [
            u"an em dash\u2014quite dashing".encode("utf-8"),
            b"oh\x82bother",
        ]

        @pytest.mark.parametrize("input_bytes", BAD_ASCII_CASES)
        def test_bad_ascii(self, input_bytes):
            """Tests cases where the input to decode_str() is invalid ASCII.
            """
            with pytest.raises(ValueError):
                protocol.decode_str(input_bytes, 0)

    def test_endtoend(self):
        """Tests string encoding end-to-end.
        """
        assert protocol.decode_str(protocol.encode_str("hello")) == ("hello", 6)


class TestPacketType(object):

    class TestEncode(object):
        NOMINAL_CASES = [
            (protocol.PacketType.RRQ, b"\x00\x01"),
            (protocol.PacketType.WRQ, b"\x00\x02"),
            (protocol.PacketType.DATA, b"\x00\x03"),
            (protocol.PacketType.ACK, b"\x00\x04"),
            (protocol.PacketType.ERROR, b"\x00\x05"),
            (protocol.PacketType.OACK, b"\x00\x06"),
        ]

        @pytest.mark.parametrize("input_type,exp_output", NOMINAL_CASES)
        def test_nominal(self, input_type, exp_output):
            """Tests nominal uses of PacketType.encode()
            """
            assert protocol.PacketType.encode(input_type) == exp_output

    class TestDecode(object):
        NOMINAL_CASES = [
            (b"\x00\x01", 0, protocol.PacketType.RRQ),
            (b"\x00\x02", 0, protocol.PacketType.WRQ),
            (b"\x00\x03", 0, protocol.PacketType.DATA),
            (b"\x00\x04", 0, protocol.PacketType.ACK),
            (b"\x00\x05", 0, protocol.PacketType.ERROR),
            (b"\x00\x06", 0, protocol.PacketType.OACK),
            (b"\xaf\x00\x06", 1, protocol.PacketType.OACK),
            (b"\x00\x01\x00\x02", 2, protocol.PacketType.WRQ),
            (b"\x00\x01\x00\x02", 0, protocol.PacketType.RRQ),
        ]

        @pytest.mark.parametrize("input_bytes,offset,exp_output", NOMINAL_CASES)
        def test_nominal(self, input_bytes, offset, exp_output):
            """Tests nominal uses of PacketType.decode()
            """
            assert protocol.PacketType.decode(input_bytes, offset) == (exp_output, offset + 2)

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
            with pytest.raises(protocol.PacketType.UnknownPacketTypeError):
                protocol.PacketType.decode(input_bytes, 0)

    @pytest.mark.parametrize("packet_type", [
        protocol.PacketType.RRQ,
        protocol.PacketType.WRQ,
        protocol.PacketType.DATA,
        protocol.PacketType.ACK,
        protocol.PacketType.ERROR,
        protocol.PacketType.OACK,
    ])
    def test_endtoend(self, packet_type):
        """Tests end-to-end encoding and decoding of packet types.
        """
        assert protocol.PacketType.decode(protocol.PacketType.encode(packet_type)) == (packet_type,
                                                                                       2)


class TestTransferMode(object):

    class TestEncode(object):
        NOMINAL_CASES = [
            (protocol.TransferMode.NETASCII, b"netascii\0"),
            (protocol.TransferMode.OCTET, b"octet\0"),
            (protocol.TransferMode.MAIL, b"mail\0"),
            (protocol.TransferMode.ASCII, b"netascii\0"),
            (protocol.TransferMode.TEXT, b"netascii\0"),
            (protocol.TransferMode.BINARY, b"octet\0"),
        ]

        @pytest.mark.parametrize("transfer_mode,exp_output", NOMINAL_CASES)
        def test_nominal(self, transfer_mode, exp_output):
            """Tests nominal uses of TransferMode.encode().
            """
            assert protocol.TransferMode.encode(transfer_mode) == exp_output

    class TestDecode(object):
        NOMINAL_CASES = [
            (b"netascii\0", 0, (protocol.TransferMode.NETASCII, 9)),
            (b"octet\0", 0, (protocol.TransferMode.OCTET, 6)),
            (b"mail\0", 0, (protocol.TransferMode.MAIL, 5)),
            (b"mail\0netascii\0", 0, (protocol.TransferMode.MAIL, 5)),
            (b"mail\0netascii\0", 5, (protocol.TransferMode.NETASCII, 14)),
        ]

        @pytest.mark.parametrize("input_bytes,offset,exp_output", NOMINAL_CASES)
        def test_nominal(self, input_bytes, offset, exp_output):
            """Tests nominal uses of PacketType.decode()
            """
            assert protocol.TransferMode.decode(input_bytes, offset) == exp_output

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
            with pytest.raises(protocol.TransferMode.UnknownTransferModeError):
                protocol.TransferMode.decode(input_bytes, offset)

    @pytest.mark.parametrize(
        "transfer_mode,exp_output",
        [
            (protocol.TransferMode.NETASCII, (protocol.TransferMode.NETASCII, 9)),
            (protocol.TransferMode.OCTET, (protocol.TransferMode.OCTET, 6)),
            (protocol.TransferMode.MAIL, (protocol.TransferMode.MAIL, 5)),
            # Unfortunately, constantly doesn't have good support for aliases, and so ASCII !=
            # NETASCII (etc.) even if that's my intention.
            (protocol.TransferMode.ASCII, (protocol.TransferMode.NETASCII, 9)),
            (protocol.TransferMode.TEXT, (protocol.TransferMode.NETASCII, 9)),
            (protocol.TransferMode.BINARY, (protocol.TransferMode.OCTET, 6)),
        ])
    def test_endtoend(self, transfer_mode, exp_output):
        """Tests end-to-end encoding and decoding of transfer mode.
        """
        assert protocol.TransferMode.decode(
            protocol.TransferMode.encode(transfer_mode)) == exp_output


class TestErrorCode(object):

    class TestEncode(object):
        NOMINAL_CASES = [
            (protocol.ErrorCode.CUSTOM, b"\x00\x00"),
            (protocol.ErrorCode.FILE_NOT_FOUND, b"\x00\x01"),
            (protocol.ErrorCode.ACCESS_VIOLATION, b"\x00\x02"),
            (protocol.ErrorCode.DISK_FULL, b"\x00\x03"),
            (protocol.ErrorCode.ILLEGAL_OP, b"\x00\x04"),
            (protocol.ErrorCode.UNKNOWN_ID, b"\x00\x05"),
            (protocol.ErrorCode.FILE_EXISTS, b"\x00\x06"),
            (protocol.ErrorCode.NO_SUCH_USER, b"\x00\x07"),
            (protocol.ErrorCode.OPTION_FAILURE, b"\x00\x08"),
        ]

        @pytest.mark.parametrize("error_code,exp_output", NOMINAL_CASES)
        def test_nominal(self, error_code, exp_output):
            """Tests nominal uses of ErrorCode.encode()
            """
            assert protocol.ErrorCode.encode(error_code) == exp_output

    class TestDecode(object):
        NOMINAL_CASES = [
            (b"\x00\x00", 0, protocol.ErrorCode.CUSTOM),
            (b"\x00\x01", 0, protocol.ErrorCode.FILE_NOT_FOUND),
            (b"\x00\x02", 0, protocol.ErrorCode.ACCESS_VIOLATION),
            (b"\x00\x03", 0, protocol.ErrorCode.DISK_FULL),
            (b"\x00\x04", 0, protocol.ErrorCode.ILLEGAL_OP),
            (b"\x00\x05", 0, protocol.ErrorCode.UNKNOWN_ID),
            (b"\x00\x06", 0, protocol.ErrorCode.FILE_EXISTS),
            (b"\x00\x07", 0, protocol.ErrorCode.NO_SUCH_USER),
            (b"\x00\x08", 0, protocol.ErrorCode.OPTION_FAILURE),
            (b"\xe0\x00\x05", 1, protocol.ErrorCode.UNKNOWN_ID),
            (b"\x00\x00\x00\x01", 0, protocol.ErrorCode.CUSTOM),
            (b"\x00\x00\x00\x01", 2, protocol.ErrorCode.FILE_NOT_FOUND),
        ]

        @pytest.mark.parametrize("input_bytes,offset,exp_output", NOMINAL_CASES)
        def test_nominal(self, input_bytes, offset, exp_output):
            """Tests nominal uses of PacketType.decode()
            """
            assert protocol.ErrorCode.decode(input_bytes, offset) == (exp_output, offset + 2)

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
            with pytest.raises(protocol.ErrorCode.UnknownErrorCodeError):
                protocol.ErrorCode.decode(input_bytes, 0)

    @pytest.mark.parametrize("error_code", [
        protocol.ErrorCode.CUSTOM,
        protocol.ErrorCode.FILE_NOT_FOUND,
        protocol.ErrorCode.ACCESS_VIOLATION,
        protocol.ErrorCode.DISK_FULL,
        protocol.ErrorCode.ILLEGAL_OP,
        protocol.ErrorCode.UNKNOWN_ID,
        protocol.ErrorCode.FILE_EXISTS,
        protocol.ErrorCode.NO_SUCH_USER,
        protocol.ErrorCode.OPTION_FAILURE,
    ])
    def test_endtoend(self, error_code):
        """Tests end-to-end encoding and decoding of error codes.
        """
        assert protocol.ErrorCode.decode(protocol.ErrorCode.encode(error_code)) == (error_code, 2)


class TestOption(object):

    class TestEncodeOption(object):
        NOMINAL_CASES = [
            ("tsize", "200", b"tsize\x00200\x00"),
            ("customoption", "value!", b"customoption\x00value!\x00"),
        ]

        @pytest.mark.parametrize("name,value,exp_output", NOMINAL_CASES)
        def test_nominal(self, name, value, exp_output):
            """Tests nominal uses of Option.encode().
            """
            assert protocol.Option(name, value).encode() == exp_output

        NULL_CASES = [
            ("first is br\x00ken", "I'm fine"),
            ("good name", "\x00bad value"),
            ("oh\x00no", "not both\x00"),
        ]

        @pytest.mark.parametrize("name,value", NULL_CASES)
        def test_null(self, name, value):
            """Tests cases where the option name or value have a null character embedded in them.
            """
            with pytest.raises(ValueError):
                protocol.Option(name, value).encode()

        BAD_ASCII_CASES = [
            ("some option", u"an em dash\u2014quite dashing"),
            ("oh\x82bother", "val"),
            ("why\xffme", u"everything is \u00e4wful"),
        ]

        @pytest.mark.parametrize("name,value", BAD_ASCII_CASES)
        def test_bad_ascii(self, name, value):
            """Tests cases where the option name or value contain invalid ASCII.
            """
            with pytest.raises(ValueError):
                protocol.Option(name, value).encode()

    class TestDecodeOption(object):
        NOMINAL_CASES = [
            (b"windowsize\x00512\x00", 0, (protocol.Option("windowsize", "512"), 15)),
            (b"octet\x00tsize\x002048\x00", 6, (protocol.Option("tsize", "2048"), 17)),
        ]

        @pytest.mark.parametrize("input_bytes,offset,exp_output", NOMINAL_CASES)
        def test_nominal(self, input_bytes, offset, exp_output):
            """Tests nominal uses of Option.decode().
            """
            assert protocol.Option.decode(input_bytes, offset) == exp_output

        MISSING_NULL_CASES = [
            (b"windowsize\x00512", 0),
            (b"windowsize 512\x00", 0),
            (b"windowsize 512", 0),
            (b"test\x00512\x00", 5),
        ]

        @pytest.mark.parametrize("input_bytes,offset", MISSING_NULL_CASES)
        def test_missing_null(self, input_bytes, offset):
            """Tests cases where null terminators were left out.
            """
            with pytest.raises(protocol.NullTerminatorNotFoundError):
                protocol.Option.decode(input_bytes, offset)

        BAD_ASCII_CASES = [
            (b"some option\x00" + u"an em dash\u2014quite dashing\x00".encode("utf-8"), 0),
            (b"oh\x82bother\x00val\x00", 0),
            (b"why\xffme\x00" + u"everything is \u00e4wful\x00".encode("utf-8"), 0),
        ]

        @pytest.mark.parametrize("input_bytes,offset", BAD_ASCII_CASES)
        def test_bad_ascii(self, input_bytes, offset):
            """Tests cases where the option name or value contain invalid ASCII.
            """
            with pytest.raises(ValueError):
                protocol.Option.decode(input_bytes, offset)

    class TestOptionMisc(object):
        EQ_NOMINAL_CASES = [
            (protocol.Option("a", "b"), protocol.Option("a", "b"), True),
            (protocol.Option("a", "b"), protocol.Option("a", "c"), False),
            (protocol.Option("a", "b"), protocol.Option("x", "b"), False),
            (protocol.Option("a", "b"), protocol.Option("x", "y"), False),
        ]

        @pytest.mark.parametrize("a,b,expected", EQ_NOMINAL_CASES)
        def test_eq(self, a, b, expected):
            """Tests the Option.__eq__() function when both self and other are Options.
            """
            assert a.__eq__(b) == expected

        @pytest.mark.parametrize("a,b,expected", EQ_NOMINAL_CASES)
        def test_ne(self, a, b, expected):
            """Tests the Option.__ne__() function when both self and other are Options.
            """
            assert a.__ne__(b) == (not expected)

        EQ_NOTIMPLEMENTED_CASES = [
            (protocol.Option("a", "b"), 3),
            (protocol.Option("a", "b"), ("a", "b")),
        ]

        @pytest.mark.parametrize("a,b", EQ_NOTIMPLEMENTED_CASES)
        def test_eq_notimplemented(self, a, b):
            """Tests the Option.__eq__() function when other is not an Option.
            """
            assert a.__eq__(b) is NotImplemented

        @pytest.mark.parametrize("a,b", EQ_NOTIMPLEMENTED_CASES)
        def test_ne_notimplemented(self, a, b):
            """Tests the Option.__ne__() function when other is not an Option.
            """
            assert a.__ne__(b) is NotImplemented

        def test_repr_coverage_only(self):
            """Runs the Option.__repr__() function just to ensure that it doesn't raise exceptions
            or cause parsing errors.
            """
            assert repr(protocol.Option("hello", "world"))

    @pytest.mark.parametrize("name,value", [
        ("name", "value"),
        ("windowsize", "32"),
        ("blksize", "2048"),
        ("timeout", "5"),
    ])
    def test_endtoend(self, name, value):
        """Tests end-to-end encoding and decoding of options.
        """
        opt = protocol.Option(name, value)
        exp_offset = len(name) + len(value) + 2
        assert protocol.Option.decode(opt.encode()) == (opt, exp_offset)


class TestRequestPacket(object):

    class TestEncode(object):
        NOMINAL_CASES = [
            ({
                "is_write": True,
                "filename": "test A",
                "mode": protocol.TransferMode.MAIL,
            }, b"\x00\x02test A\x00mail\x00"),
            ({
                "is_write": False,
                "filename": "config",
                "mode": protocol.TransferMode.NETASCII,
            }, b"\x00\x01config\x00netascii\x00"),
            (
                {
                    "is_write": True,
                    "filename": "bob@example.org",
                    "mode": protocol.TransferMode.MAIL,
                    # OrderedDict is necessary to ensure that the options are enumerated in a
                    # predictable order.
                    "options": OrderedDict([
                        ("tsize", "304"),
                        ("blocksize", "2048"),
                    ])
                },
                b"\x00\x02bob@example.org\x00mail\x00tsize\x00304\x00blocksize\x002048\x00"),
            (
                {
                    "is_write": False,
                    "filename": "config",
                    "mode": protocol.TransferMode.NETASCII,
                    # OrderedDict is necessary to ensure that the options are enumerated in a
                    # predictable order.
                    "options": OrderedDict([
                        ("timeout", "5"),
                        ("windowsize", "16"),
                    ])
                },
                b"\x00\x01config\x00netascii\x00timeout\x005\x00windowsize\x0016\x00"),
        ]

        @pytest.mark.parametrize("packet_kwargs,exp_output", NOMINAL_CASES)
        def test_nominal(self, packet_kwargs, exp_output):
            """Tests nominal encoding of RequestPackets.
            """
            assert protocol.RequestPacket(**packet_kwargs).encode() == exp_output

    class TestDecode(object):
        NOMINAL_CASES = [
            (b"\x00\x01purpose\x00netascii\x00", 0, {
                "is_write": False,
                "filename": "purpose",
                "mode": protocol.TransferMode.NETASCII,
            }),
            (b"\x00\x02application\x00octet\x00", 0, {
                "is_write": True,
                "filename": "application",
                "mode": protocol.TransferMode.OCTET,
            }),
            (b"\x00\x02application\x00octet\x00"
             b"tsize\x0043221030\x00blksize\x001428\x00windowsize\x0016\x00", 0, {
                 "is_write": True,
                 "filename": "application",
                 "mode": protocol.TransferMode.OCTET,
                 "options": {
                     "tsize": "43221030",
                     "blksize": "1428",
                     "windowsize": "16",
                 }
             }),
        ]

        @pytest.mark.parametrize("packet,offset,exp_output_kwargs", NOMINAL_CASES)
        def test_nominal(self, packet, offset, exp_output_kwargs):
            """Tests nominal decoding of RequestPackets.
            """
            exp_output = protocol.RequestPacket(**exp_output_kwargs)
            decoded, _ = protocol.RequestPacket.decode(packet, offset)
            assert (decoded.is_write == exp_output.is_write and
                    decoded.options == exp_output.options and
                    decoded.filename == exp_output.filename and decoded.mode == exp_output.mode)

        BAD_VALUE_CASES = [
            (b"\x00\x03dowhat\x00netascii\x00",
             ValueError),  # Wrong packet type (correct structure)
            (b"\x00\x01another\x00invalid\x00", protocol.TransferMode.UnknownTransferModeError),
        ]

        @pytest.mark.parametrize("packet,exp_error", BAD_VALUE_CASES)
        def test_bad_values(self, packet, exp_error):
            """Tests the behaviour of RequestPacket.decode() when given input with invalid values.
            """
            with pytest.raises(exp_error):
                protocol.RequestPacket.decode(packet)

        BAD_STRUCTURE_CASES = [
            (b"\x00\x01uh oh the string isn't terminated", protocol.NullTerminatorNotFoundError),
            (b"\x00\x02nomode??\x00", protocol.NullTerminatorNotFoundError),
            (b"\x00\x01", protocol.NullTerminatorNotFoundError),  # No file name or transfer mode
            (b"", protocol.struct.error),  # Entirely empty
        ]

        @pytest.mark.parametrize("packet,exp_error", BAD_STRUCTURE_CASES)
        def test_bad_structure(self, packet, exp_error):
            """Tests the behaviour of RequestPacket.decode() when given badly structured input.
            """
            with pytest.raises(exp_error):
                protocol.RequestPacket.decode(packet)

    def test_repr_coverage_only(self):
        """Runs the RequestPacket.__repr__() function just to ensure that it doesn't raise
        exceptions or cause parsing errors.
        """
        assert repr(protocol.RequestPacket(True, "file", protocol.TransferMode.ASCII))


class TestErrorPacket(object):

    class TestEncode(object):
        NOMINAL_CASES = [
            ({
                "code": protocol.ErrorCode.FILE_NOT_FOUND,
                "message": "File not found",
            }, b"\x00\x05\x00\x01File not found\x00"),
            ({
                "code": protocol.ErrorCode.CUSTOM,
                "message": "Hi there!",
            }, b"\x00\x05\x00\x00Hi there!\x00"),
            ({
                "code": protocol.ErrorCode.OPTION_FAILURE,
                "message": "windowsize too small",
            }, b"\x00\x05\x00\x08windowsize too small\x00"),
        ]

        @pytest.mark.parametrize("packet_kwargs,exp_output", NOMINAL_CASES)
        def test_nominal(self, packet_kwargs, exp_output):
            """Tests nominal encoding of ErrorPackets.
            """
            assert protocol.ErrorPacket(**packet_kwargs).encode() == exp_output

    class TestDecode(object):
        NOMINAL_CASES = [
            (b"\x00\x05\x00\x00This is a custom error\x00", 0, {
                "code": protocol.ErrorCode.CUSTOM,
                "message": "This is a custom error",
            }),
            (b"\x00\x05\x00\x06This file already exists.\x00", 0, {
                "code": protocol.ErrorCode.FILE_EXISTS,
                "message": "This file already exists.",
            }),
        ]

        @pytest.mark.parametrize("packet,offset,exp_output_kwargs", NOMINAL_CASES)
        def test_nominal(self, packet, offset, exp_output_kwargs):
            """Tests nominal decoding of ErrorPackets.
            """
            exp_output = protocol.ErrorPacket(**exp_output_kwargs)
            decoded, _ = protocol.ErrorPacket.decode(packet, offset)
            assert (decoded.code == exp_output.code and decoded.message == exp_output.message)

        BAD_VALUE_CASES = [
            (b"\x00\x01\x00\x00what?\x00", ValueError),  # Wrong packet type (correct structure)
            (b"\x00\x05\x00\x20strange error\x00", protocol.ErrorCode.UnknownErrorCodeError),
        ]

        @pytest.mark.parametrize("packet,exp_error", BAD_VALUE_CASES)
        def test_bad_values(self, packet, exp_error):
            """Tests the behaviour of ErrorPacket.decode() when given input with invalid values.
            """
            with pytest.raises(exp_error):
                protocol.ErrorPacket.decode(packet)

        BAD_STRUCTURE_CASES = [
            (b"\x00\x05\x00\x02", protocol.NullTerminatorNotFoundError),  # No error message
            (b"\x00\x05", protocol.struct.error),  # No error code
            (b"", protocol.struct.error),  # Entirely empty
        ]

        @pytest.mark.parametrize("packet,exp_error", BAD_STRUCTURE_CASES)
        def test_bad_structure(self, packet, exp_error):
            """Tests the behaviour of ErrorPacket.decode() when given badly structured input.
            """
            with pytest.raises(exp_error):
                protocol.ErrorPacket.decode(packet)

    def test_repr_coverage_only(self):
        """Runs the ErrorPacket.__repr__() function just to ensure that it doesn't raise exceptions
        or cause parsing errors.
        """
        assert repr(protocol.ErrorPacket(protocol.ErrorCode.NO_SUCH_USER, "No such user"))
