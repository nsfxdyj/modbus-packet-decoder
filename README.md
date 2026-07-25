# Modbus Packet Decoder

A lightweight, **dependency-free** CLI tool to parse and analyze Modbus TCP/RTU packets from hex strings or binary files. Built for embedded & industrial IoT engineers who debug protocol traffic daily.

![CI](https://github.com/nsfxdyj/modbus-packet-decoder/actions/workflows/ci.yml/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Features

- **Auto-detect** Modbus TCP (MBAP header) vs Modbus RTU (CRC16) frames
- **Decode common function codes**: 01–06, 15, 16 + exception responses
- **Smart payload interpretation**: register values as unsigned, signed, and Float32-BE
- **Colorized terminal output** (auto-disabled when piped)
- **JSON export** for CI pipelines or further processing
- **CSV export** for spreadsheet analysis and batch reporting
- **Batch mode** – process multiple hex lines from a text file in one shot
- **Transparent TCP proxy** – sit between an HMI/SCADA and a PLC to see live traffic
- **Zero dependencies** – pure Python 3.8+

## Install

```bash
# Clone or download the single file
git clone https://github.com/nsfxdyj/modbus-packet-decoder.git
cd modbus-packet-decoder
python modbus_packet_decoder.py --help
```

No `pip install` required. If you prefer:

```bash
chmod +x modbus_packet_decoder.py
sudo ln -s $(pwd)/modbus_packet_decoder.py /usr/local/bin/modbus-decode
```

## Quick Start

### 1. Decode a Modbus TCP request from hex

```bash
python modbus_packet_decoder.py "00 01 00 00 00 06 01 03 00 00 00 0A"
```

Output:
```
════════════════════════════════════════════════════════════
  Frame Type : TCP
  Raw Hex    : 00010000000601030000000a
  MBAP Header:
    Transaction ID : 1
    Protocol ID    : 0 (Modbus)
    Length         : 6 bytes
    Unit ID        : 1
  Function   : 0x03 – Read Holding Registers
    starting_address: 0
    quantity        : 10
════════════════════════════════════════════════════════════
```

### 2. Decode a Modbus RTU response (with CRC check)

```bash
python modbus_packet_decoder.py "01 03 04 00 64 00 C8 BA 7A"
```

Output:
```
════════════════════════════════════════════════════════════
  Frame Type : RTU
  Raw Hex    : 010304006400c8ba7a
  Slave ID   : 1
  CRC        : 0x7ABA (VALID)
  Function   : 0x03 – Read Holding Registers
    byte_count      : 4
    Register values : [100, 200]
    Signed          : [100, 200]
════════════════════════════════════════════════════════════
```

### 3. Read from a binary capture file

```bash
python modbus_packet_decoder.py --file capture.bin --json output.json
```

### 4. Pipe from another tool

```bash
echo "00010000000601030000000A" | python modbus_packet_decoder.py -
```

### 5. Batch-process a log file and export to CSV

Create a text file `packets.txt`:
```
# Site A – morning samples
00 01 00 00 00 06 01 03 00 00 00 0A
01 03 04 00 64 00 C8 BA 7A

# Site B – afternoon samples
00 02 00 00 00 06 01 04 00 00 00 05
```

Run:
```bash
python modbus_packet_decoder.py --batch packets.txt --csv report.csv
```

Resulting `report.csv` contains one row per packet with frame type, MBAP/RTU metadata, function code, and a JSON payload column for easy pivoting in Excel or Pandas.

### 6. Run as a transparent TCP proxy (live debugging)

Place the tool between your Modbus client (HMI/SCADA) and the PLC:

```bash
# The real PLC is at 192.168.1.100:502
# Proxy listens on port 1502 and forwards everything to the PLC
python modbus_packet_decoder.py --proxy --target-host 192.168.1.100 --target-port 502 --listen-port 1502
```

Now point your HMI to `your-laptop-ip:1502` instead of the PLC directly. Every request and response is decoded and printed in real time:

```
Modbus TCP Proxy listening on 0.0.0.0:1502
Forwarding to 192.168.1.100:502
Press Ctrl+C to stop

Client connected: 192.168.1.50:49152

════════════════════════════════════════════════════════════
  Frame Type : TCP
  Raw Hex    : 00010000000601030000000a
  MBAP Header:
    Transaction ID : 1
    Protocol ID    : 0 (Modbus)
    Length         : 6 bytes
    Unit ID        : 1
  Function   : 0x03 – Read Holding Registers
    starting_address: 0
    quantity        : 10
════════════════════════════════════════════════════════════
[C→S] TCP frame forwarded (12 bytes)

════════════════════════════════════════════════════════════
  Frame Type : TCP
  Raw Hex    : 000100000017010314006400c8007b00000000000000000000
  MBAP Header:
    Transaction ID : 1
    Protocol ID    : 0 (Modbus)
    Length         : 23 bytes
    Unit ID        : 1
  Function   : 0x03 – Read Holding Registers
    byte_count      : 20
    Register values : [100, 200, 123, 0, 0, 0, 0, 0, 0, 0]
    Signed          : [100, 200, 123, 0, 0, 0, 0, 0, 0, 0]
════════════════════════════════════════════════════════════
[S→C] TCP frame forwarded (29 bytes)

Client disconnected: 192.168.1.50:49152
```

The proxy handles **TCP stickiness and splitting** automatically, so even if the OS delivers multiple Modbus frames in a single `recv()` or splits one frame across two, each frame is extracted and decoded individually.

## Supported Function Codes

| Code | Name | Decode Details |
|------|------|----------------|
| 0x01 | Read Coils | Starting address, quantity |
| 0x02 | Read Discrete Inputs | Starting address, quantity |
| 0x03 | Read Holding Registers | Starting address, quantity; response: register values + signed + float32 |
| 0x04 | Read Input Registers | Same as 0x03 |
| 0x05 | Write Single Coil | Address, ON/OFF state |
| 0x06 | Write Single Register | Address, value |
| 0x0F | Write Multiple Coils | Starting address, quantity, byte count |
| 0x10 | Write Multiple Registers | Starting address, quantity, byte count |
| 0x8X | Exception Response | Exception code + name |

## CLI Reference

```
usage: modbus_packet_decoder [-h] [--file FILE] [--batch BATCH] [--json JSON]
                             [--csv CSV] [--no-color] [--version]
                             [--proxy] [--target-host TARGET_HOST]
                             [--target-port TARGET_PORT]
                             [--listen-port LISTEN_PORT]
                             [input]

positional arguments:
  input                 Hex string or '-' for stdin

optional arguments:
  -h, --help            show this help message and exit
  -f, --file FILE       Read binary packet data from file
  -b, --batch BATCH     Read multiple hex lines from text file (one per line,
                        # comments supported)
  -j, --json JSON       Export decoded results to JSON file
  -c, --csv CSV         Export decoded results to CSV file
  --no-color            Disable colorized output
  --version             show program's version number and exit

Proxy mode:
  --proxy               Run as a transparent Modbus TCP proxy with real-time
                        decoding
  --target-host TARGET_HOST
                        Target Modbus server host (default: 127.0.0.1)
  --target-port TARGET_PORT
                        Target Modbus server port (default: 502)
  --listen-port LISTEN_PORT
                        Local listen port for proxy mode (default: 1502)
```

## JSON Output Example

```json
[
  {
    "frame_type": "TCP",
    "raw_hex": "00010000000601030000000a",
    "mbap": {
      "transaction_id": 1,
      "protocol_id": 0,
      "length": 6,
      "unit_id": 1
    },
    "pdu": {
      "function_code": 3,
      "function_name": "Read Holding Registers",
      "is_exception": false,
      "data_hex": "0000000a",
      "starting_address": 0,
      "quantity": 10
    }
  }
]
```

## CSV Output Example

| line | frame_type | raw_hex | slave_id | transaction_id | protocol_id | length | unit_id | function_code | function_name | is_exception | exception_code | exception_name | crc | crc_valid | error | payload_json |
|------|------------|---------|----------|----------------|-------------|--------|---------|---------------|---------------|--------------|----------------|----------------|-----|-----------|-------|--------------|
| 1 | RTU | 010304006400c8ba7a | 1 | | | | | 3 | Read Holding Registers | False | | | 0x7ABA | True | | {"byte_count": 4, "register_values": [100, 200], ...} |

## Development

```bash
# Install test dependencies
pip install -r requirements-dev.txt

# Run tests
pytest -v

# Run with coverage
pytest -v --cov=modbus_packet_decoder --cov-report=term-missing

# Run lint / type-check (optional)
python -m py_compile modbus_packet_decoder.py
```

## Use Cases

- Debugging Modbus traffic from serial sniffers or TCP dumps
- Validating PLC / HMI communication in the field
- Writing unit tests for Modbus client libraries
- Batch-analysing protocol logs from SCADA or gateway devices
- Quick sanity checks without firing up Wireshark
- **Live field debugging** by placing the proxy between HMI and PLC

## License

MIT © 2026 nsfxdyj
