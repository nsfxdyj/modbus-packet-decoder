#!/usr/bin/env python3
"""
Unit tests for Modbus Packet Decoder.

Run with:  python -m pytest -v
"""

import sys
import json
from pathlib import Path

# Ensure the module under test is importable.
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

from modbus_packet_decoder import (
    MBAPHeader,
    PDU,
    DecodedFrame,
    Colors,
    color,
    hex_to_bytes,
    crc16_modbus,
    detect_and_parse,
    _parse_tcp,
    _parse_rtu,
    _to_signed,
    _to_float32,
    _bytes_to_bits,
    FUNCTION_NAMES,
    EXCEPTION_CODES,
    print_frame,
    main,
    build_parser,
    _export_csv,
)


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

class TestColorsAndHelpers:
    def test_color(self):
        assert color("hello", Colors.RED) == f"{Colors.RED}hello{Colors.RESET}"

    def test_hex_to_bytes_plain(self):
        assert hex_to_bytes("0001FF0A") == b"\x00\x01\xff\x0a"

    def test_hex_to_bytes_with_spaces(self):
        assert hex_to_bytes("00 01 FF 0A") == b"\x00\x01\xff\x0a"

    def test_hex_to_bytes_with_prefix(self):
        assert hex_to_bytes("0x00 0x01 0xFF 0x0A") == b"\x00\x01\xff\x0a"

    def test_hex_to_bytes_odd_length_raises(self):
        try:
            hex_to_bytes("001")
            assert False, "Expected ValueError"
        except ValueError as e:
            assert "odd length" in str(e)

    def test_bytes_to_bits(self):
        assert _bytes_to_bits(b"\x05", 8) == [1, 0, 1, 0, 0, 0, 0, 0]
        assert _bytes_to_bits(b"\x03", 2) == [1, 1]
        assert _bytes_to_bits(b"\x00", 4) == [0, 0, 0, 0]

    def test_to_signed(self):
        assert _to_signed(0) == 0
        assert _to_signed(32767) == 32767
        assert _to_signed(32768) == -32768
        assert _to_signed(65535) == -1

    def test_to_float32_valid(self):
        # 0x4040_0000 = 3.0 in IEEE 754 big-endian
        assert _to_float32(0x4040, 0x0000) == 3.0
        # 0x3F80_0000 = 1.0
        assert _to_float32(0x3F80, 0x0000) == 1.0

    def test_to_float32_zero(self):
        assert _to_float32(0x0000, 0x0000) == 0.0

    def test_crc16_modbus_known(self):
        # CRC for slave_id=1, fc=3, 0x00, 0x00, 0x00, 0x0A should be 0xC40A
        data = bytes([0x01, 0x03, 0x00, 0x00, 0x00, 0x0A])
        crc = crc16_modbus(data)
        assert crc == 0xC40A


# ---------------------------------------------------------------------------
# MBAP Header
# ---------------------------------------------------------------------------

class TestMBAPHeader:
    def test_parse_valid(self):
        data = bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01])
        h = MBAPHeader.parse(data)
        assert h.transaction_id == 1
        assert h.protocol_id == 0
        assert h.length == 6
        assert h.unit_id == 1

    def test_parse_too_short(self):
        try:
            MBAPHeader.parse(b"\x00\x01\x00")
            assert False, "Expected ValueError"
        except ValueError as e:
            assert "too short" in str(e)

    def test_to_dict(self):
        h = MBAPHeader(2, 0, 8, 3)
        assert h.to_dict() == {
            "transaction_id": 2,
            "protocol_id": 0,
            "length": 8,
            "unit_id": 3,
        }


# ---------------------------------------------------------------------------
# PDU
# ---------------------------------------------------------------------------

class TestPDU:
    def test_parse_normal(self):
        pdu = PDU.parse(bytes([0x03, 0x00, 0x00, 0x00, 0x0A]))
        assert pdu.function_code == 3
        assert pdu.is_exception is False

    def test_parse_exception(self):
        pdu = PDU.parse(bytes([0x83, 0x02]))
        assert pdu.function_code == 3
        assert pdu.is_exception is True
        assert pdu.exception_code == 2
        assert pdu.exception_name == "Illegal Data Address"

    def test_decode_payload_fc03_response(self):
        pdu = PDU.parse(bytes([0x03, 0x04, 0x00, 0x64, 0x00, 0xC8]))
        d = pdu.to_dict()
        assert d["function_name"] == "Read Holding Registers"
        assert d["byte_count"] == 4
        assert d["register_values"] == [100, 200]
        assert d["as_signed"] == [100, 200]
        assert d["as_float32_be"] == [100.0]

    def test_decode_payload_fc03_request(self):
        pdu = PDU.parse(bytes([0x03, 0x00, 0x00, 0x00, 0x0A]))
        d = pdu.to_dict()
        assert d["starting_address"] == 0
        assert d["quantity"] == 10

    def test_decode_payload_fc01_response(self):
        # 1 coil byte (0x05) representing 5 coils: 1,0,1,0,0,0,0,0
        pdu = PDU.parse(bytes([0x01, 0x01, 0x05]))
        d = pdu.to_dict()
        assert d["byte_count"] == 1
        assert d["coil_values"] == [1, 0, 1, 0, 0, 0, 0, 0]

    def test_decode_payload_fc05(self):
        pdu = PDU.parse(bytes([0x05, 0x00, 0x0A, 0xFF, 0x00]))
        d = pdu.to_dict()
        assert d["address"] == 10
        assert d["value"] == 0xFF00
        assert d["value_desc"] == "ON"

    def test_decode_payload_fc06(self):
        pdu = PDU.parse(bytes([0x06, 0x00, 0x0A, 0x00, 0x7B]))
        d = pdu.to_dict()
        assert d["address"] == 10
        assert d["value"] == 123

    def test_decode_payload_fc16(self):
        pdu = PDU.parse(bytes([0x10, 0x00, 0x0A, 0x00, 0x02, 0x04]))
        d = pdu.to_dict()
        assert d["starting_address"] == 10
        assert d["quantity"] == 2
        assert d["byte_count"] == 4

    def test_exception_to_dict(self):
        pdu = PDU.parse(bytes([0x83, 0x03]))
        d = pdu.to_dict()
        assert d["is_exception"] is True
        assert d["exception_code"] == 3
        assert d["exception_name"] == "Illegal Data Value"


# ---------------------------------------------------------------------------
# Frame detection & parsing
# ---------------------------------------------------------------------------

class TestFrameDetection:
    def test_detect_tcp(self):
        data = bytes([
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01,
            0x03, 0x00, 0x00, 0x00, 0x0A,
        ])
        frame = detect_and_parse(data)
        assert frame.frame_type == "TCP"
        assert frame.mbap is not None
        assert frame.mbap.transaction_id == 1

    def test_detect_rtu_valid_crc(self):
        data = bytes([0x01, 0x03, 0x04, 0x00, 0x64, 0x00, 0xC8, 0xBA, 0x7A])
        frame = detect_and_parse(data)
        assert frame.frame_type == "RTU"
        assert frame.crc_valid is True
        assert frame.slave_id == 1

    def test_detect_rtu_invalid_crc(self):
        data = bytes([0x01, 0x03, 0x04, 0x00, 0x64, 0x00, 0xC8, 0xDE, 0xAD])
        frame = detect_and_parse(data)
        assert frame.frame_type == "RTU"
        assert frame.crc_valid is False

    def test_detect_too_short(self):
        frame = detect_and_parse(b"\x01")
        assert frame.frame_type == "UNKNOWN"

    def test_parse_tcp_explicit(self):
        data = bytes([
            0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x03,
            0x04, 0x00, 0x00, 0x00, 0x05,
        ])
        frame = _parse_tcp(data)
        assert frame.frame_type == "TCP"
        assert frame.pdu.function_code == 4

    def test_parse_rtu_explicit(self):
        payload = bytes([0x01, 0x06, 0x00, 0x0A, 0x00, 0x7B])
        crc = crc16_modbus(payload).to_bytes(2, "little")
        data = payload + crc
        frame = _parse_rtu(data, crc_valid=True)
        assert frame.frame_type == "RTU"
        assert frame.pdu.function_code == 6


# ---------------------------------------------------------------------------
# Batch & CSV export
# ---------------------------------------------------------------------------

class TestBatchCSV:
    def test_batch_file(self, tmp_path, capsys):
        batch_file = tmp_path / "packets.txt"
        batch_file.write_text(
            "# comment\n"
            "00 01 00 00 00 06 01 03 00 00 00 0A\n"
            "\n"
            "01 03 04 00 64 00 C8 BA 7A\n"
        )
        ret = main(["--batch", str(batch_file)])
        assert ret == 0
        captured = capsys.readouterr()
        assert "TCP" in captured.out
        assert "RTU" in captured.out

    def test_batch_csv_export(self, tmp_path, capsys):
        batch_file = tmp_path / "packets.txt"
        batch_file.write_text("01 03 04 00 64 00 C8 BA 7A\n")
        csv_file = tmp_path / "out.csv"
        ret = main(["--batch", str(batch_file), "--csv", str(csv_file)])
        assert ret == 0
        assert csv_file.exists()
        content = csv_file.read_text()
        assert "frame_type" in content
        assert "RTU" in content
        captured = capsys.readouterr()
        assert "CSV exported" in captured.out

    def test_batch_file_not_found(self, capsys):
        ret = main(["--batch", "nonexistent.txt"])
        assert ret == 1
        captured = capsys.readouterr()
        assert "Error" in captured.err

    def test_export_csv_direct(self, tmp_path):
        data = bytes([0x01, 0x03, 0x04, 0x00, 0x64, 0x00, 0xC8, 0xBA, 0x7A])
        frame = detect_and_parse(data)
        csv_file = tmp_path / "direct.csv"
        _export_csv([frame], str(csv_file))
        content = csv_file.read_text()
        assert "frame_type,raw_hex" in content
        assert "RTU" in content
        assert "0x7ABA" in content


# ---------------------------------------------------------------------------
# CLI / integration
# ---------------------------------------------------------------------------

class TestCLI:
    def test_parser_help(self, capsys):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--help"])

    def test_parser_version(self, capsys):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--version"])

    def test_main_tcp_hex(self, capsys):
        ret = main(["00 01 00 00 00 06 01 03 00 00 00 0A"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "TCP" in captured.out
        assert "Read Holding Registers" in captured.out

    def test_main_rtu_hex(self, capsys):
        ret = main(["01 03 04 00 64 00 C8 BA 7A"])
        assert ret == 0
        captured = capsys.readouterr()
        assert "RTU" in captured.out
        assert "VALID" in captured.out

    def test_main_no_args(self, capsys):
        ret = main([])
        assert ret == 0
        captured = capsys.readouterr()
        assert "usage:" in captured.out

    def test_main_json_export(self, tmp_path, capsys):
        json_file = tmp_path / "out.json"
        ret = main(["--json", str(json_file), "01 03 04 00 64 00 C8 BA 7A"])
        assert ret == 0
        assert json_file.exists()
        data = json.loads(json_file.read_text())
        assert isinstance(data, list)
        assert data[0]["frame_type"] == "RTU"
        captured = capsys.readouterr()
        assert "JSON exported" in captured.out

    def test_main_file_input(self, tmp_path, capsys):
        bin_file = tmp_path / "packet.bin"
        bin_file.write_bytes(bytes([
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01,
            0x03, 0x00, 0x00, 0x00, 0x0A,
        ]))
        ret = main(["--file", str(bin_file)])
        assert ret == 0
        captured = capsys.readouterr()
        assert "TCP" in captured.out

    def test_main_invalid_hex(self, capsys):
        ret = main(["GGG"])
        assert ret == 1
        captured = capsys.readouterr()
        assert "Error" in captured.err

    def test_main_stdin(self, capsys, monkeypatch):
        monkeypatch.setattr(sys, "stdin", type("FakeStdin", (), {
            "read": lambda self: "010304006400C8BA7A",
            "isatty": lambda self: False,
        })())
        ret = main([])
        assert ret == 0
        captured = capsys.readouterr()
        assert "RTU" in captured.out


# ---------------------------------------------------------------------------
# Pretty printer (smoke tests – mainly ensure no crash)
# ---------------------------------------------------------------------------

class TestPrettyPrinter:
    def test_print_tcp_frame(self, capsys):
        data = bytes([
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01,
            0x03, 0x00, 0x00, 0x00, 0x0A,
        ])
        frame = detect_and_parse(data)
        print_frame(frame, use_color=False)
        captured = capsys.readouterr()
        assert "TCP" in captured.out

    def test_print_exception_frame(self, capsys):
        data = bytes([
            0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x01,
            0x83, 0x02,
        ])
        frame = detect_and_parse(data)
        print_frame(frame, use_color=False)
        captured = capsys.readouterr()
        assert "EXCEPTION" in captured.out
        assert "Illegal Data Address" in captured.out

    def test_print_unknown_frame(self, capsys):
        frame = DecodedFrame(frame_type="UNKNOWN", raw_hex="01", error="Too short")
        print_frame(frame, use_color=False)
        captured = capsys.readouterr()
        assert "UNKNOWN" in captured.out
        assert "Too short" in captured.out


# ---------------------------------------------------------------------------
# Lookup tables completeness
# ---------------------------------------------------------------------------

class TestLookupTables:
    def test_function_names_not_empty(self):
        assert len(FUNCTION_NAMES) > 0
        assert 3 in FUNCTION_NAMES

    def test_exception_codes_not_empty(self):
        assert len(EXCEPTION_CODES) > 0
        assert 1 in EXCEPTION_CODES
        assert EXCEPTION_CODES[1] == "Illegal Function"


import pytest
