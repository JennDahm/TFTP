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

from tftp import protocol, primitives


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
            with pytest.raises(primitives.NullTerminatorNotFoundError):
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
                "mode": primitives.TransferMode.MAIL,
            }, b"\x00\x02test A\x00mail\x00"),
            ({
                "is_write": False,
                "filename": "config",
                "mode": primitives.TransferMode.NETASCII,
            }, b"\x00\x01config\x00netascii\x00"),
            (
                {
                    "is_write": True,
                    "filename": "bob@example.org",
                    "mode": primitives.TransferMode.MAIL,
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
                    "mode": primitives.TransferMode.NETASCII,
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
                "mode": primitives.TransferMode.NETASCII,
            }),
            (b"\x00\x02application\x00octet\x00", 0, {
                "is_write": True,
                "filename": "application",
                "mode": primitives.TransferMode.OCTET,
            }),
            (b"\x00\x02application\x00octet\x00"
             b"tsize\x0043221030\x00blksize\x001428\x00windowsize\x0016\x00", 0, {
                 "is_write": True,
                 "filename": "application",
                 "mode": primitives.TransferMode.OCTET,
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
            (b"\x00\x01another\x00invalid\x00", primitives.TransferMode.UnknownTransferModeError),
        ]

        @pytest.mark.parametrize("packet,exp_error", BAD_VALUE_CASES)
        def test_bad_values(self, packet, exp_error):
            """Tests the behaviour of RequestPacket.decode() when given input with invalid values.
            """
            with pytest.raises(exp_error):
                protocol.RequestPacket.decode(packet)

        BAD_STRUCTURE_CASES = [
            (b"\x00\x01uh oh the string isn't terminated", primitives.NullTerminatorNotFoundError),
            (b"\x00\x02nomode??\x00", primitives.NullTerminatorNotFoundError),
            (b"\x00\x01", primitives.NullTerminatorNotFoundError),  # No file name or transfer mode
            (b"", primitives.struct.error),  # Entirely empty
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
        assert repr(protocol.RequestPacket(True, "file", primitives.TransferMode.ASCII))


class TestErrorPacket(object):

    class TestEncode(object):
        NOMINAL_CASES = [
            ({
                "code": primitives.ErrorCode.FILE_NOT_FOUND,
                "message": "File not found",
            }, b"\x00\x05\x00\x01File not found\x00"),
            ({
                "code": primitives.ErrorCode.CUSTOM,
                "message": "Hi there!",
            }, b"\x00\x05\x00\x00Hi there!\x00"),
            ({
                "code": primitives.ErrorCode.OPTION_FAILURE,
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
                "code": primitives.ErrorCode.CUSTOM,
                "message": "This is a custom error",
            }),
            (b"\x00\x05\x00\x06This file already exists.\x00", 0, {
                "code": primitives.ErrorCode.FILE_EXISTS,
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
            (b"\x00\x05\x00\x20strange error\x00", primitives.ErrorCode.UnknownErrorCodeError),
        ]

        @pytest.mark.parametrize("packet,exp_error", BAD_VALUE_CASES)
        def test_bad_values(self, packet, exp_error):
            """Tests the behaviour of ErrorPacket.decode() when given input with invalid values.
            """
            with pytest.raises(exp_error):
                protocol.ErrorPacket.decode(packet)

        BAD_STRUCTURE_CASES = [
            (b"\x00\x05\x00\x02", primitives.NullTerminatorNotFoundError),  # No error message
            (b"\x00\x05", primitives.struct.error),  # No error code
            (b"", primitives.struct.error),  # Entirely empty
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
        assert repr(protocol.ErrorPacket(primitives.ErrorCode.NO_SUCH_USER, "No such user"))


class TestDataPacket(object):

    class TestEncode(object):
        NOMINAL_CASES = [
            ({
                "block_num": 33,
                "data": b"some test data",
            }, b"\x00\x03\x00\x21some test data"),
        ]

        @pytest.mark.parametrize("packet_kwargs,exp_output", NOMINAL_CASES)
        def test_nominal(self, packet_kwargs, exp_output):
            """Tests nominal encoding of DataPackets.
            """
            assert protocol.DataPacket(**packet_kwargs).encode() == exp_output

        BAD_VALUE_CASES = [
            ({
                "block_num": 0,
                "data": b"block numbers start at 1!",
            }, ValueError),
            ({
                "block_num": 77777,
                "data": b"Too big for a uint16",
            }, primitives.struct.error),
            ({
                "block_num": -22,
                "data": b"Too negative for a uint16",
            }, primitives.struct.error),
            # I would also test non-byte-strings, but in Python2, bytes == str.
        ]

        @pytest.mark.parametrize("packet_kwargs,exp_error", BAD_VALUE_CASES)
        def test_bad_values(self, packet_kwargs, exp_error):
            """Tests nominal encoding of DataPackets.
            """
            with pytest.raises(exp_error):
                protocol.DataPacket(**packet_kwargs).encode()

    class TestDecode(object):
        NOMINAL_CASES = [
            (b"\x00\x03\x00\x21some test data", 0, {
                "block_num": 33,
                "data": b"some test data",
            }),
            (b"\x00\x03\xff\xff", 0, {
                "block_num": 0xffff,
                "data": b"",  # No data is perfectly fine!
            }),
            (b"\x12\x34\x56\x00\x03\x00\x21some test data", 3, {
                "block_num": 33,
                "data": b"some test data",
            }),
        ]

        @pytest.mark.parametrize("packet,offset,exp_output_kwargs", NOMINAL_CASES)
        def test_nominal(self, packet, offset, exp_output_kwargs):
            """Tests nominal decoding of DataPackets.
            """
            exp_output = protocol.DataPacket(**exp_output_kwargs)
            decoded, next_offset = protocol.DataPacket.decode(packet, offset)
            assert next_offset == len(packet)  # DataPackets parse all the way to the end.
            assert (decoded.block_num == exp_output.block_num and decoded.data == exp_output.data)

        BAD_VALUE_CASES = [
            (b"\x00\x01\x00\x01wrong packet type", 0, ValueError),
            (b"\x12\x34\x00\x01unknown type", 0, primitives.PacketType.UnknownPacketTypeError),
            (b"\x00\x03\x00\x00block nums start at 1", 0, ValueError),
        ]

        @pytest.mark.parametrize("packet,offset,exp_error", BAD_VALUE_CASES)
        def test_bad_values(self, packet, offset, exp_error):
            """Tests the behaviour of DataPacket.decode() when given input with invalid values.
            """
            with pytest.raises(exp_error):
                protocol.DataPacket.decode(packet)

        BAD_STRUCTURE_CASES = [
            (b"\x00\x03", 0, primitives.struct.error),  # Missing "block num" field
            (b"", 0, primitives.struct.error),  # Missing "packet type" field
            (b"\x00\x03", 2, primitives.struct.error),  # Missing "packet type" field after offset
        ]

        @pytest.mark.parametrize("packet,offset,exp_error", BAD_STRUCTURE_CASES)
        def test_bad_structure(self, packet, offset, exp_error):
            """Tests the behaviour of DataPacket.decode() when given input with bad structure.
            """
            with pytest.raises(exp_error):
                protocol.DataPacket.decode(packet)

    def test_repr_coverage_only(self):
        """Runs the DataPacket.__repr__() function just to ensure that it doesn't raise exceptions
        or cause parsing errors.
        """
        assert repr(protocol.DataPacket(30, b"This is some binary data"))
