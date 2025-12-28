#!/usr/bin/env python3
"""
ESP32 UDP Client Script
Connects to ESP32 UDP server and receives/unpacks structured packets

Supports two modes:
1. Regular UDP server mode (port 3333): Send messages and receive heartbeat/ACK responses
2. CSI streaming mode (port 3334): Receive WiFi CSI (Channel State Information) data packets

Packet format (matches esp32_base.c packet_t structure):
- magic: uint16_t (network byte order - big-endian)
- version: uint8_t
- type: uint8_t (HEARTBEAT, DATA, ACK, or CSI)
- seq: uint32_t (network byte order - big-endian)
- timestamp: uint64_t (host byte order - little-endian on ESP32)
- payload_len: uint16_t (network byte order - big-endian)
- payload: variable length array

CSI payload structure (when type is PKT_TYPE_CSI):
- timestamp: uint64_t (microseconds, little-endian)
- rssi: int8_t (signal strength in dBm)
- channel: uint8_t (WiFi channel number)
- len: uint8_t (actual CSI data length)
- data: int8_t[128] (CSI data array, first 'len' bytes are valid)
"""

import socket
import struct
import sys
from datetime import datetime

# Packet constants (must match esp32_base.c definitions)
PKT_MAGIC = 0xCAFE
PKT_TYPE_HEARTBEAT = 0x01
PKT_TYPE_DATA = 0x02
PKT_TYPE_ACK = 0x03
PKT_TYPE_CSI = 0x04

# UDP ports (must match esp32_base.c definitions)
UDP_PORT = 3333          # Regular UDP server port
UDP_CSI_PORT = 3334      # CSI streaming port

# CSI payload structure size
MAX_CSI_LEN = 128        # Maximum CSI data length (must match esp32_base.c)
CSI_PAYLOAD_SIZE = 8 + 1 + 1 + 1 + MAX_CSI_LEN  # timestamp(8) + rssi(1) + channel(1) + len(1) + data(128)

# Packet header size (fixed fields only, excluding variable payload)
# magic(2) + version(1) + type(1) + seq(4) + timestamp(8) + payload_len(2) = 18 bytes
PKT_HEADER_SIZE = 18

# Packet type names for display
PKT_TYPE_NAMES = {
    PKT_TYPE_HEARTBEAT: "HEARTBEAT",
    PKT_TYPE_DATA: "DATA",
    PKT_TYPE_ACK: "ACK",
    PKT_TYPE_CSI: "CSI"
}


def unpack_packet(data):
    """
    Unpack the ESP32 packet structure from received bytes.
    
    Args:
        data: Bytes received from UDP socket
        
    Returns:
        Dictionary with unpacked packet fields, or None if invalid
    """
    if len(data) < PKT_HEADER_SIZE:
        print(f"Error: Packet too short ({len(data)} bytes, expected at least {PKT_HEADER_SIZE})")
        return None
    
    # Unpack fixed header fields
    # Note: Python struct module doesn't support mixing endianness in one format string,
    # so we unpack fields separately or use intermediate unpacking
    
    # Bytes 0-7: magic(2) + version(1) + type(1) + seq(4)
    # Unpack: magic(>H big-endian), version(B), type(B), seq(>I big-endian)
    magic, version, pkt_type = struct.unpack('>HBB', data[0:4])
    seq = struct.unpack('>I', data[4:8])[0]  # '>I' = big-endian uint32_t
    
    # Bytes 8-15: timestamp (8 bytes, little-endian on ESP32)
    timestamp = struct.unpack('<Q', data[8:16])[0]  # '<Q' = little-endian uint64_t
    
    # Bytes 16-17: payload_len (2 bytes, big-endian)
    payload_len = struct.unpack('>H', data[16:18])[0]  # '>H' = big-endian uint16_t
    
    # Validate magic number
    if magic != PKT_MAGIC:
        print(f"Error: Invalid magic number 0x{magic:04X} (expected 0x{PKT_MAGIC:04X})")
        return None
    
    # Extract payload if present
    payload = None
    if payload_len > 0:
        if len(data) < PKT_HEADER_SIZE + payload_len:
            print(f"Warning: Packet incomplete (got {len(data)} bytes, expected {PKT_HEADER_SIZE + payload_len})")
        else:
            payload = data[PKT_HEADER_SIZE:PKT_HEADER_SIZE + payload_len]
    
    return {
        'magic': magic,
        'version': version,
        'type': pkt_type,
        'seq': seq,
        'timestamp': timestamp,
        'payload_len': payload_len,
        'payload': payload
    }


def format_timestamp(timestamp_us):
    """
    Format timestamp (microseconds) into human-readable format.
    
    Args:
        timestamp_us: Timestamp in microseconds since ESP32 boot
        
    Returns:
        Formatted string with seconds and milliseconds
    """
    seconds = timestamp_us // 1000000
    milliseconds = (timestamp_us % 1000000) // 1000
    return f"{seconds}.{milliseconds:03d}s"


def unpack_csi_payload(data):
    """
    Unpack CSI payload structure from bytes.
    
    Structure (matches esp32_base.c csi_payload_t):
    - timestamp: uint64_t (8 bytes, little-endian)
    - rssi: int8_t (1 byte, signed)
    - channel: uint8_t (1 byte)
    - len: uint8_t (1 byte) - actual data length
    - data: int8_t[MAX_CSI_LEN] (128 bytes, but only first 'len' bytes are valid)
    
    Args:
        data: Bytes containing CSI payload (should be CSI_PAYLOAD_SIZE bytes)
        
    Returns:
        Dictionary with unpacked CSI fields, or None if invalid
    """
    if len(data) < CSI_PAYLOAD_SIZE:
        print(f"Warning: CSI payload too short ({len(data)} bytes, expected {CSI_PAYLOAD_SIZE})")
        return None
    
    # Unpack CSI payload structure
    # timestamp (8 bytes, little-endian uint64_t)
    timestamp = struct.unpack('<Q', data[0:8])[0]
    
    # rssi (1 byte, signed int8)
    rssi = struct.unpack('b', data[8:9])[0]
    
    # channel (1 byte, unsigned)
    channel = struct.unpack('B', data[9:10])[0]
    
    # len (1 byte, unsigned) - actual data length
    data_len = struct.unpack('B', data[10:11])[0]
    
    # Extract CSI data (int8_t array, actual length is in 'len' field)
    # Limit to actual length and max CSI length
    actual_len = min(data_len, MAX_CSI_LEN)
    csi_data = [struct.unpack('b', data[11 + i:11 + i + 1])[0] for i in range(actual_len)]
    
    return {
        'timestamp': timestamp,
        'rssi': rssi,
        'channel': channel,
        'len': data_len,
        'data': csi_data
    }


def print_packet(packet, remote_addr):
    """
    Print packet information in a formatted way.
    
    Args:
        packet: Dictionary with unpacked packet fields
        remote_addr: Tuple (host, port) of the sender
    """
    print("\n" + "="*60)
    print(f"Packet received from {remote_addr[0]}:{remote_addr[1]}")
    print("="*60)
    print(f"Magic:         0x{packet['magic']:04X}")
    print(f"Version:       {packet['version']}")
    print(f"Type:          {packet['type']} ({PKT_TYPE_NAMES.get(packet['type'], 'UNKNOWN')})")
    print(f"Sequence:      {packet['seq']}")
    print(f"Timestamp:     {packet['timestamp']} us ({format_timestamp(packet['timestamp'])})")
    print(f"Payload Len:   {packet['payload_len']} bytes")
    
    # Handle different packet types
    if packet['type'] == PKT_TYPE_CSI and packet['payload']:
        # Unpack and display CSI payload
        csi = unpack_csi_payload(packet['payload'])
        if csi:
            print("\n--- CSI Data ---")
            print(f"CSI Timestamp:  {csi['timestamp']} us ({format_timestamp(csi['timestamp'])})")
            print(f"RSSI:           {csi['rssi']} dBm")
            print(f"Channel:        {csi['channel']}")
            print(f"Data Length:    {csi['len']} bytes")
            print(f"CSI Data (first 32 values): {csi['data'][:32]}")
            if len(csi['data']) > 32:
                print(f"                ... ({len(csi['data']) - 32} more values)")
            # Display as hex if user wants to see raw data
            if len(csi['data']) <= 64:  # Only show hex for smaller datasets
                csi_hex = ' '.join(f'{b:02X}' if b >= 0 else f'{256+b:02X}' for b in csi['data'][:32])
                print(f"CSI Data (hex): {csi_hex}")
    elif packet['payload']:
        # For other packet types, display payload as hex and ASCII
        payload_hex = ' '.join(f'{b:02X}' for b in packet['payload'][:64])  # Limit display
        if len(packet['payload']) > 64:
            payload_hex += f" ... ({len(packet['payload']) - 64} more bytes)"
        payload_ascii = ''.join(chr(b) if 32 <= b < 127 else '.' for b in packet['payload'][:64])
        if len(packet['payload']) > 64:
            payload_ascii += "..."
        print(f"Payload (hex): {payload_hex}")
        print(f"Payload (str): {payload_ascii}")
    else:
        print("Payload:       (empty)")
    
    print("="*60)


def main():
    """Main function to connect to ESP32 and receive packets."""
    # Parse command line arguments
    if len(sys.argv) < 2:
        print("Usage: python3 udp_client.py <ESP32_IP_ADDRESS> [port] [--csi]")
        print(f"Example: python3 udp_client.py 192.168.1.100")
        print(f"         python3 udp_client.py 192.168.1.100 {UDP_PORT}")
        print(f"         python3 udp_client.py 192.168.1.100 {UDP_CSI_PORT} --csi")
        print(f"\nPorts:")
        print(f"  {UDP_PORT} - Regular UDP server (heartbeat/ack packets)")
        print(f"  {UDP_CSI_PORT} - CSI streaming port")
        print(f"\nDefault port: {UDP_PORT}")
        sys.exit(1)
    
    esp32_ip = sys.argv[1]
    
    # Check for --csi flag or determine port
    use_csi = '--csi' in sys.argv
    if len(sys.argv) > 2 and sys.argv[2] != '--csi':
        port = int(sys.argv[2])
        use_csi = use_csi or (port == UDP_CSI_PORT)
    elif use_csi:
        port = UDP_CSI_PORT
    else:
        port = UDP_PORT
    
    mode_str = "CSI streaming" if use_csi else "UDP server"
    print(f"Connecting to ESP32 at {esp32_ip}:{port} ({mode_str})")
    
    if use_csi:
        print("Listening for CSI data packets...")
    else:
        print("Send any message to trigger ESP32 response...")
    print("Press Ctrl+C to exit\n")
    
    try:
        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # For CSI mode, bind to receive packets (broadcast or unicast)
        if use_csi:
            # Bind to all interfaces (0.0.0.0) to receive packets sent to our IP or broadcast
            sock.bind(('0.0.0.0', port))
            # Enable SO_REUSEADDR to allow binding even if port is in use
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            print(f"Bound to port {port} for CSI reception (listening on all interfaces)")
        else:
            # Set socket timeout (optional, but useful for responsiveness)
            sock.settimeout(1.0)
            
            # Send initial message to trigger ESP32 response
            test_message = b"Hello ESP32"
            print(f"Sending: {test_message.decode()}")
            sock.sendto(test_message, (esp32_ip, port))
        
        packet_count = 0
        csi_count = 0
        heartbeat_count = 0
        
        # Main receive loop
        while True:
            try:
                # Receive data from ESP32 (larger buffer for CSI packets)
                buffer_size = 2048 if use_csi else 1024
                data, addr = sock.recvfrom(buffer_size)
                packet_count += 1
                
                print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Received {len(data)} bytes from {addr[0]}:{addr[1]}")
                
                # Unpack the packet
                packet = unpack_packet(data)
                
                if packet:
                    # Count packet types
                    if packet['type'] == PKT_TYPE_CSI:
                        csi_count += 1
                    elif packet['type'] == PKT_TYPE_HEARTBEAT:
                        heartbeat_count += 1
                    
                    print_packet(packet, addr)
                    
                    # For non-CSI packets, send acknowledgment
                    if not use_csi and packet['type'] != PKT_TYPE_CSI:
                        response = f"ACK_{packet['seq']}".encode()
                        sock.sendto(response, addr)
                        print(f"Sent response: {response.decode()}")
                else:
                    print("Failed to unpack packet")
                    
            except socket.timeout:
                # Timeout is normal, just continue
                continue
            except KeyboardInterrupt:
                print("\n\nInterrupted by user")
                break
            except Exception as e:
                print(f"\nError receiving packet: {e}")
                import traceback
                traceback.print_exc()
                continue
        
        print(f"\n{'='*60}")
        print(f"Total packets received: {packet_count}")
        print(f"  - CSI packets: {csi_count}")
        print(f"  - Heartbeat packets: {heartbeat_count}")
        print(f"  - Other packets: {packet_count - csi_count - heartbeat_count}")
        print(f"{'='*60}")
        
    except socket.error as e:
        print(f"Socket error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    finally:
        sock.close()
        print("Socket closed")


if __name__ == "__main__":
    main()

