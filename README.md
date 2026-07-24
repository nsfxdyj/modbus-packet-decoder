# Modbus Packet Decoder

A lightweight, **dependency-free** CLI tool to parse and analyze Modbus TCP/RTU packets from hex strings or binary files. Built for embedded & industrial IoT engineers who debug protocol traffic daily.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Features

- **Auto-detect** Modbus TCP (MBAP header) vs Modbus RTU (CRC16) frames
- **Decode common function codes**: 01–06, 15, 16 + exception responses
- **Smart payload interpretation**: register values as unsigned, signed, and Float32-BE
- **Colorized terminal output** (auto-disabled when piped)
- **JSON export** for CI pipelines or further processing
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
usage: modbus_packet_decoder [-h] [--file FILE] [--json JSON] [--no-color] [--version] [input]

positional arguments:
  input         Hex string or '-' for stdin

optional arguments:
  -h, --help    show this help message and exit
  -f, --file    Read binary packet data from file
  -j, --json    Export decoded results to JSON file
  --no-color    Disable colorized output
  --version     show program's version number and exit
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

## Use Cases

- Debugging Modbus traffic from serial sniffers or TCP dumps
- Validating PLC / HMI communication in the field
- Writing unit tests for Modbus client libraries
- Quick sanity checks without firing up Wireshark

## License

MIT © 2026 nsfxdyj
