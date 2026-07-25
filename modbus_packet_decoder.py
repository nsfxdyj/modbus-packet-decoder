#!/usr/bin/env python3
"""
Modbus Packet Decoder
=====================
A lightweight, dependency-free CLI tool to parse and analyze Modbus TCP/RTU
packets from hex strings or binary files.

Supports common function codes (01-06, 15, 16), colorized terminal output,
JSON/CSV export for further processing or CI pipelines, and a transparent
TCP proxy mode for real-time field debugging.

Author: nsfxdyj
License: MIT
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import socket
import sys
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List, Optional

__version__ = "1.2.0"

# ---------------------------------------------------------------------------
# Color helpers (no external deps)
# ---------------------------------------------------------------------------

class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    DIM = "\033[2m"


def color(text: str, c: str) -> str:
    return f"{c}{text}{Colors.RESET}"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class MBAPHeader:
    """Modbus TCP Application Protocol header (7 bytes)."""
    transaction_id: int
    protocol_id: int
    length: int
    unit_id: int

    @staticmethod
    def parse(data: bytes) -> MBAPHeader:
        if len(data) < 7:
            raise ValueError(f"MBAP header too short ({len(data)} bytes)")
        return MBAPHeader(
            transaction_id=int.from_bytes(data[0:2], "big"),
            protocol_id=int.from_bytes(data[2:4], "big"),
            length=int.from_bytes(data[4:6], "big"),
            unit_id=data[6],
        )

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PDU:
    """Protocol Data Unit (function code + data)."""
    function_code: int
    is_exception: bool = False
    data: bytes = b""
    exception_code: Optional[int] = None
    exception_name: Optional[str] = None

    @staticmethod
    def parse(data: bytes) -> PDU:
        if len(data) < 1:
            raise ValueError("PDU empty")
        fc = data[0]
        is_exc = (fc & 0x80) != 0
        pdu = PDU(function_code=fc & 0x7F, is_exception=is_exc, data=data[1:])
        if is_exc:
            pdu.exception_code = data[1] if len(data) > 1 else None
            pdu.exception_name = EXCEPTION_CODES.get(pdu.exception_code, "Unknown")
        return pdu

    def to_dict(self) -> dict:
        d = {
            "function_code": self.function_code,
            "function_name": FUNCTION_NAMES.get(self.function_code, "Unknown"),
            "is_exception": self.is_exception,
            "data_hex": self.data.hex(),
        }
        if self.is_exception:
            d["exception_code"] = self.exception_code
            d["exception_name"] = self.exception_name
        else:
            d.update(self._decode_payload())
        return d

    def _decode_payload(self) -> dict:
        """Attempt to decode the payload based on function code."""
        fc = self.function_code
        data = self.data
        result: dict = {}

        if fc in (1, 2, 3, 4):
            # Distinguish request vs response for read function codes.
            # Response: first byte is byte_count, remaining is data.
            # Request: 2 bytes start address + 2 bytes quantity.
            is_response = False
            if len(data) >= 1:
                byte_count = data[0]
                expected_len = 1 + byte_count
                if fc in (3, 4):
                    # Holding / Input Registers: byte_count must be even, <= 250
                    if byte_count % 2 == 0 and byte_count <= 250 and len(data) == expected_len:
                        is_response = True
                else:
                    # Coils / Discrete Inputs: byte_count <= 250
                    if byte_count <= 250 and len(data) == expected_len:
                        is_response = True

            if is_response:
                result["byte_count"] = data[0]
                if fc in (1, 2):
                    bits = _bytes_to_bits(data[1:], result["byte_count"] * 8)
                    result["coil_values"] = bits[:result["byte_count"] * 8]
                else:  # fc 3, 4
                    regs = []
                    for i in range(1, len(data), 2):
                        if i + 1 < len(data):
                            regs.append(int.from_bytes(data[i:i+2], "big"))
                    result["register_values"] = regs
                    if regs:
                        result["as_signed"] = [_to_signed(v) for v in regs]
                        if len(regs) % 2 == 0:
                            result["as_float32_be"] = [_to_float32(regs[i], regs[i+1]) for i in range(0, len(regs), 2)]
            elif len(data) >= 4:
                # Request interpretation
                result["starting_address"] = int.from_bytes(data[0:2], "big")
                result["quantity"] = int.from_bytes(data[2:4], "big")

        elif fc == 5:
            if len(data) >= 4:
                result["address"] = int.from_bytes(data[0:2], "big")
                val = int.from_bytes(data[2:4], "big")
                result["value"] = val
                result["value_desc"] = "ON" if val == 0xFF00 else "OFF" if val == 0x0000 else f"0x{val:04X}"

        elif fc == 6:
            if len(data) >= 4:
                result["address"] = int.from_bytes(data[0:2], "big")
                result["value"] = int.from_bytes(data[2:4], "big")

        elif fc in (15, 16):
            if len(data) >= 5:
                result["starting_address"] = int.from_bytes(data[0:2], "big")
                result["quantity"] = int.from_bytes(data[2:4], "big")
                result["byte_count"] = data[4]

        return result


def _bytes_to_bits(data: bytes, n: int) -> List[int]:
    bits = []
    for b in data:
        for i in range(8):
            bits.append((b >> i) & 1)
            if len(bits) >= n:
                return bits
    return bits


def _to_signed(v: int) -> int:
    return v - 65536 if v > 32767 else v


def _to_float32(hi: int, lo: int) -> Optional[float]:
    import struct
    try:
        packed = struct.pack(">HH", hi, lo)
        return struct.unpack(">f", packed)[0]
    except Exception:
        return None


# ---------------------------------------------------------------------------
# CRC16 (Modbus RTU)
# ---------------------------------------------------------------------------

def crc16_modbus(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc


# ---------------------------------------------------------------------------
# TCP Stream frame extraction (handles TCP stickiness / splitting)
# ---------------------------------------------------------------------------

def extract_tcp_frames(buffer: bytearray) -> List[bytes]:
    """Extract complete Modbus TCP frames from a bytearray buffer.

    Modbus TCP frames are prefixed by a 7-byte MBAP header.  Bytes 5-6
    (big-endian) give the *remaining* length (unit_id + PDU).  The total
    frame size is therefore 6 + length.  This function removes complete
    frames from *buffer* (in place) and returns them as a list.

    Example – two back-to-back frames in one recv():
        >>> buf = bytearray(b'\\x00\\x01\\x00\\x00\\x00\\x06\\x01\\x03\\x00\\x00\\x00\\x0A'
        ...                 b'\\x00\\x02\\x00\\x00\\x00\\x06\\x01\\x04\\x00\\x00\\x00\\x05')
        >>> extract_tcp_frames(buf)
        [b'...12 bytes...', b'...12 bytes...']
        >>> len(buf)
        0
    """
    frames: List[bytes] = []
    while len(buffer) >= 7:
        length = int.from_bytes(buffer[4:6], "big")
        frame_len = 6 + length
        if len(buffer) >= frame_len:
            frames.append(bytes(buffer[:frame_len]))
            del buffer[:frame_len]
        else:
            break
    return frames


# ---------------------------------------------------------------------------
# Lookup tables
# ---------------------------------------------------------------------------

FUNCTION_NAMES = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    17: "Report Slave ID",
    20: "Read File Record",
    21: "Write File Record",
    22: "Mask Write Register",
    23: "Read/Write Multiple Registers",
    24: "Read FIFO Queue",
    43: "Read Device Identification",
}

EXCEPTION_CODES = {
    1: "Illegal Function",
    2: "Illegal Data Address",
    3: "Illegal Data Value",
    4: "Slave Device Failure",
    5: "Acknowledge",
    6: "Slave Device Busy",
    7: "Negative Acknowledge",
    8: "Memory Parity Error",
    10: "Gateway Path Unavailable",
    11: "Gateway Target Device Failed",
}


# ---------------------------------------------------------------------------
# Frame detection & parsing
# ---------------------------------------------------------------------------

@dataclass
class DecodedFrame:
    frame_type: str          # "TCP" or "RTU"
    raw_hex: str
    mbap: Optional[MBAPHeader] = None
    slave_id: Optional[int] = None
    pdu: Optional[PDU] = None
    crc: Optional[int] = None
    crc_valid: Optional[bool] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        d: dict = {"frame_type": self.frame_type, "raw_hex": self.raw_hex}
        if self.mbap:
            d["mbap"] = self.mbap.to_dict()
        if self.slave_id is not None:
            d["slave_id"] = self.slave_id
        if self.pdu:
            d["pdu"] = self.pdu.to_dict()
        if self.crc is not None:
            d["crc"] = f"0x{self.crc:04X}"
            d["crc_valid"] = self.crc_valid
        if self.error:
            d["error"] = self.error
        return d


def hex_to_bytes(text: str) -> bytes:
    """Convert various hex string formats to bytes."""
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", text)
    if len(cleaned) % 2 != 0:
        raise ValueError("Hex string has odd length")
    return bytes.fromhex(cleaned)


def detect_and_parse(data: bytes) -> DecodedFrame:
    """Auto-detect Modbus TCP vs RTU and parse accordingly."""
    if len(data) < 2:
        return DecodedFrame(frame_type="UNKNOWN", raw_hex=data.hex(), error="Too short")

    if len(data) >= 7:
        proto_id = int.from_bytes(data[2:4], "big")
        length = int.from_bytes(data[4:6], "big")
        if proto_id == 0 and 1 <= length <= 260 and len(data) == 6 + length:
            return _parse_tcp(data)

    if len(data) >= 4:
        payload = data[:-2]
        received_crc = int.from_bytes(data[-2:], "little")
        computed_crc = crc16_modbus(payload)
        if received_crc == computed_crc:
            return _parse_rtu(data, crc_valid=True)

    if len(data) >= 8:
        try:
            return _parse_tcp(data)
        except Exception:
            pass

    if len(data) >= 4:
        try:
            return _parse_rtu(data, crc_valid=False)
        except Exception:
            pass

    return DecodedFrame(frame_type="UNKNOWN", raw_hex=data.hex(), error="Unable to detect frame type")


def _parse_tcp(data: bytes) -> DecodedFrame:
    if len(data) < 8:
        raise ValueError("Modbus TCP frame too short")
    mbap = MBAPHeader.parse(data)
    pdu_data = data[7:7 + mbap.length - 1]
    if len(pdu_data) < mbap.length - 1:
        raise ValueError("MBAP length mismatch")
    return DecodedFrame(
        frame_type="TCP",
        raw_hex=data.hex(),
        mbap=mbap,
        pdu=PDU.parse(pdu_data),
    )


def _parse_rtu(data: bytes, crc_valid: bool) -> DecodedFrame:
    if len(data) < 4:
        raise ValueError("Modbus RTU frame too short")
    slave_id = data[0]
    pdu_data = data[1:-2]
    crc = int.from_bytes(data[-2:], "little")
    return DecodedFrame(
        frame_type="RTU",
        raw_hex=data.hex(),
        slave_id=slave_id,
        pdu=PDU.parse(pdu_data),
        crc=crc,
        crc_valid=crc_valid,
    )


# ---------------------------------------------------------------------------
# Pretty printer
# ---------------------------------------------------------------------------

def print_frame(frame: DecodedFrame, use_color: bool = True) -> None:
    def c(text: str, col: str) -> str:
        return color(text, col) if use_color else text

    print()
    print(c("═" * 60, Colors.CYAN))
    ft_label = c(frame.frame_type, Colors.GREEN if frame.frame_type == "TCP" else Colors.YELLOW)
    print(f"  Frame Type : {ft_label}")
    print(f"  Raw Hex    : {c(frame.raw_hex, Colors.DIM)}")

    if frame.error:
        print(f"  {c('Error:', Colors.RED)} {frame.error}")
        print(c("═" * 60, Colors.CYAN))
        return

    if frame.mbap:
        mb = frame.mbap
        print(f"  MBAP Header:")
        print(f"    Transaction ID : {mb.transaction_id}")
        print(f"    Protocol ID    : {mb.protocol_id} (Modbus)")
        print(f"    Length         : {mb.length} bytes")
        print(f"    Unit ID        : {mb.unit_id}")

    if frame.slave_id is not None:
        crc_status = c("VALID", Colors.GREEN) if frame.crc_valid else c("INVALID", Colors.RED)
        print(f"  Slave ID   : {frame.slave_id}")
        print(f"  CRC        : 0x{frame.crc:04X} ({crc_status})")

    if frame.pdu:
        pdu = frame.pdu
        fc_name = FUNCTION_NAMES.get(pdu.function_code, "Unknown")
        if pdu.is_exception:
            exc_str = f"0x{pdu.exception_code:02X}" if pdu.exception_code is not None else "N/A"
            print(f"  Function   : {c(f'0x{pdu.function_code:02X} ({fc_name})', Colors.YELLOW)} {c('[EXCEPTION]', Colors.RED)}")
            print(f"  Exception  : {c(exc_str, Colors.RED)} – {pdu.exception_name or 'Unknown'}")
        else:
            print(f"  Function   : {c(f'0x{pdu.function_code:02X}', Colors.GREEN)} – {fc_name}")
            payload = pdu._decode_payload()
            for key, val in payload.items():
                if key in ("coil_values", "register_values", "as_signed", "as_float32_be"):
                    continue
                print(f"    {key:18s}: {val}")
            if "register_values" in payload:
                vals = payload["register_values"]
                print(f"    Register values : {vals}")
                if "as_signed" in payload:
                    print(f"    Signed          : {payload['as_signed']}")
                if "as_float32_be" in payload:
                    floats = [f"{v:.4f}" if v is not None else "NaN" for v in payload["as_float32_be"]]
                    print(f"    Float32 (BE)    : {floats}")
            if "coil_values" in payload:
                coils = payload["coil_values"]
                print(f"    Coil values     : {coils}")

    print(c("═" * 60, Colors.CYAN))


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------

def _export_csv(frames: List[DecodedFrame], path: str) -> None:
    """Export a list of decoded frames to CSV."""
    headers = [
        "line", "frame_type", "raw_hex",
        "slave_id", "transaction_id", "protocol_id", "length", "unit_id",
        "function_code", "function_name", "is_exception",
        "exception_code", "exception_name",
        "crc", "crc_valid", "error", "payload_json",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for i, frame in enumerate(frames, 1):
            mbap = frame.mbap
            pdu = frame.pdu
            payload_json = ""
            if pdu and not pdu.is_exception:
                payload_json = json.dumps(pdu._decode_payload(), ensure_ascii=False)
            writer.writerow([
                i,
                frame.frame_type,
                frame.raw_hex,
                frame.slave_id if frame.slave_id is not None else "",
                mbap.transaction_id if mbap else "",
                mbap.protocol_id if mbap else "",
                mbap.length if mbap else "",
                mbap.unit_id if mbap else "",
                pdu.function_code if pdu else "",
                FUNCTION_NAMES.get(pdu.function_code, "Unknown") if pdu else "",
                pdu.is_exception if pdu else "",
                pdu.exception_code if pdu and pdu.is_exception else "",
                pdu.exception_name if pdu and pdu.is_exception else "",
                f"0x{frame.crc:04X}" if frame.crc is not None else "",
                frame.crc_valid if frame.crc_valid is not None else "",
                frame.error or "",
                payload_json,
            ])


# ---------------------------------------------------------------------------
# Modbus TCP Transparent Proxy (real-time decoding)
# ---------------------------------------------------------------------------

class ProxyPipe(threading.Thread):
    """Forward data from *src* to *dst*, extracting and printing Modbus TCP frames."""

    def __init__(
        self,
        src: socket.socket,
        dst: socket.socket,
        label: str,
        use_color: bool = True,
    ) -> None:
        super().__init__(daemon=True)
        self.src = src
        self.dst = dst
        self.label = label          # e.g. "C→S" or "S→C"
        self.use_color = use_color
        self._buffer = bytearray()
        self._running = True

    def run(self) -> None:
        c = lambda text, col: color(text, col) if self.use_color else text
        while self._running:
            try:
                chunk = self.src.recv(4096)
                if not chunk:
                    break
                self._buffer.extend(chunk)
                frames = extract_tcp_frames(self._buffer)
                for frame in frames:
                    decoded = detect_and_parse(frame)
                    print_frame(decoded, self.use_color)
                    tag = c(f"[{self.label}]", Colors.MAGENTA)
                    print(
                        f"{tag} {decoded.frame_type} frame "
                        f"forwarded ({len(frame)} bytes)\n"
                    )
                self.dst.sendall(chunk)
            except OSError:
                break
            except Exception as e:
                print(
                    f"[{self.label}] Error: {e}",
                    file=sys.stderr,
                )
                break
        self._running = False

    def stop(self) -> None:
        self._running = False
        try:
            self.src.shutdown(socket.SHUT_RD)
        except OSError:
            pass


def run_proxy(
    listen_port: int,
    target_host: str,
    target_port: int,
    use_color: bool = True,
) -> None:
    """Run a transparent Modbus TCP proxy with real-time decoding.

    The proxy listens on *listen_port* and forwards every byte to
    *target_host*:*target_port*.  All Modbus TCP frames that pass
    through are decoded and printed in real time, making this ideal
    for field debugging between an HMI/SCADA and a PLC.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", listen_port))
    server.listen(5)

    c = lambda text, col: color(text, col) if use_color else text
    print(c(f"Modbus TCP Proxy listening on 0.0.0.0:{listen_port}", Colors.GREEN))
    print(c(f"Forwarding to {target_host}:{target_port}", Colors.GREEN))
    print(c("Press Ctrl+C to stop", Colors.DIM))
    print()

    try:
        while True:
            client_sock, addr = server.accept()
            print(c(f"Client connected: {addr[0]}:{addr[1]}", Colors.CYAN))

            try:
                target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                target_sock.connect((target_host, target_port))
            except Exception as e:
                print(
                    c(f"Failed to connect to target: {e}", Colors.RED),
                    file=sys.stderr,
                )
                client_sock.close()
                continue

            pipe_cs = ProxyPipe(client_sock, target_sock, "C→S", use_color)
            pipe_sc = ProxyPipe(target_sock, client_sock, "S→C", use_color)
            pipe_cs.start()
            pipe_sc.start()

            # Wait until at least one pipe dies (connection closed by either side)
            while pipe_cs.is_alive() and pipe_sc.is_alive():
                pipe_cs.join(timeout=0.5)

            pipe_cs.stop()
            pipe_sc.stop()
            try:
                client_sock.close()
            except OSError:
                pass
            try:
                target_sock.close()
            except OSError:
                pass
            print(c(f"Client disconnected: {addr[0]}:{addr[1]}", Colors.YELLOW))
            print()
    except KeyboardInterrupt:
        print()
        print(c("Shutting down proxy...", Colors.YELLOW))
    finally:
        server.close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="modbus_packet_decoder",
        description="Decode Modbus TCP/RTU packets from hex strings or binary files. "
                    "Optionally run as a transparent TCP proxy for real-time debugging.",
    )
    p.add_argument("input", nargs="?", help="Hex string (e.g. '00010000000601030000000A') or '-' for stdin")
    p.add_argument("--file", "-f", help="Read binary packet data from file")
    p.add_argument("--batch", "-b", help="Read multiple hex lines from text file (one per line, # comments supported)")
    p.add_argument("--json", "-j", help="Export decoded results to JSON file")
    p.add_argument("--csv", "-c", help="Export decoded results to CSV file")
    p.add_argument("--no-color", action="store_true", help="Disable colorized output")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    # Proxy mode
    proxy = p.add_argument_group("Proxy mode")
    proxy.add_argument("--proxy", action="store_true",
                       help="Run as a transparent Modbus TCP proxy with real-time decoding")
    proxy.add_argument("--target-host", default="127.0.0.1",
                       help="Target Modbus server host (default: 127.0.0.1)")
    proxy.add_argument("--target-port", type=int, default=502,
                       help="Target Modbus server port (default: 502)")
    proxy.add_argument("--listen-port", type=int, default=1502,
                       help="Local listen port for proxy mode (default: 1502)")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    use_color = not args.no_color and sys.stdout.isatty()

    # Proxy mode takes precedence over all other modes
    if args.proxy:
        run_proxy(args.listen_port, args.target_host, args.target_port, use_color)
        return 0

    frames: List[DecodedFrame] = []

    if args.batch:
        if not Path(args.batch).exists():
            print(f"Error: batch file not found: {args.batch}", file=sys.stderr)
            return 1
        with open(args.batch, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    data = hex_to_bytes(line)
                    frame = detect_and_parse(data)
                    frames.append(frame)
                    print_frame(frame, use_color)
                except Exception as e:
                    print(f"Error parsing line {line_num}: {e}", file=sys.stderr)
    elif args.file:
        with open(args.file, "rb") as f:
            data = f.read()
        frame = detect_and_parse(data)
        frames.append(frame)
        print_frame(frame, use_color)
    elif args.input == "-" or (args.input is None and not sys.stdin.isatty()):
        raw = sys.stdin.read()
        try:
            data = hex_to_bytes(raw)
            frame = detect_and_parse(data)
            frames.append(frame)
            print_frame(frame, use_color)
        except Exception as e:
            print(f"Error parsing stdin: {e}", file=sys.stderr)
            return 1
    elif args.input:
        try:
            data = hex_to_bytes(args.input)
            frame = detect_and_parse(data)
            frames.append(frame)
            print_frame(frame, use_color)
        except Exception as e:
            print(f"Error parsing input: {e}", file=sys.stderr)
            return 1
    else:
        parser.print_help()
        return 0

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump([f.to_dict() for f in frames], f, indent=2)
        print(f"\nJSON exported to {args.json}")

    if args.csv:
        _export_csv(frames, args.csv)
        print(f"\nCSV exported to {args.csv}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
