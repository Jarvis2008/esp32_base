#!/usr/bin/env python3
"""
ESP32 CSI Visualizer
Real-time visualization of WiFi Channel State Information (CSI) data

Features:
- Real-time amplitude vs subcarrier plot (frequency domain)
- Real-time amplitude vs time plot (time domain)
- RSSI tracking over time
- Motion detection through CSI variation

CSI data format: Complex numbers as interleaved I/Q pairs
- Even indices: Real (I) component
- Odd indices: Imaginary (Q) component
- Amplitude = sqrt(I^2 + Q^2)
- Phase = atan2(Q, I)

Usage:
    python3 csi_visualizer.py                    # Listen on port 3334
    python3 csi_visualizer.py --port 3334        # Explicit port
    python3 csi_visualizer.py --no-plot          # Console only (no GUI)
"""

import socket
import struct
import sys
import time
import numpy as np
from collections import deque
from datetime import datetime
import argparse
import threading

# Try to import matplotlib (optional for console-only mode)
try:
    import matplotlib.pyplot as plt
    import matplotlib.animation as animation
    from matplotlib.gridspec import GridSpec
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("Warning: matplotlib not installed. Install with: pip install matplotlib")
    print("Running in console-only mode.\n")

# ============================================================================
# Constants (must match esp32_base.c)
# ============================================================================

PKT_MAGIC = 0xCAFE
PKT_TYPE_CSI = 0x04
PKT_HEADER_SIZE = 18  # magic(2) + version(1) + type(1) + seq(4) + timestamp(8) + payload_len(2)
MAX_CSI_LEN = 128
CSI_PAYLOAD_SIZE = 8 + 1 + 1 + 1 + MAX_CSI_LEN  # timestamp + rssi + channel + len + data

UDP_CSI_PORT = 3334

# Visualization settings
MAX_TIME_SAMPLES = 100      # Number of time samples to keep for time-domain plot
UPDATE_INTERVAL_MS = 50     # Matplotlib update interval in milliseconds
SUBCARRIER_COUNT = 64       # Number of subcarriers (MAX_CSI_LEN / 2 for I/Q pairs)

# ============================================================================
# CSI Data Processing
# ============================================================================

class CSIProcessor:
    """Process and store CSI data for visualization."""
    
    def __init__(self, max_time_samples=MAX_TIME_SAMPLES):
        self.max_time_samples = max_time_samples
        
        # Current CSI frame
        self.current_amplitudes = np.zeros(SUBCARRIER_COUNT)
        self.current_phases = np.zeros(SUBCARRIER_COUNT)
        self.current_rssi = 0
        self.current_channel = 0
        self.current_timestamp = 0
        
        # Time series data (for amplitude vs time plot)
        self.time_data = deque(maxlen=max_time_samples)
        self.amplitude_history = deque(maxlen=max_time_samples)  # Mean amplitude per frame
        self.rssi_history = deque(maxlen=max_time_samples)
        
        # Per-subcarrier amplitude history (for heatmap or specific subcarrier tracking)
        self.subcarrier_history = deque(maxlen=max_time_samples)
        
        # Statistics
        self.packet_count = 0
        self.start_time = time.time()
        self.last_timestamp = 0
        
        # Lock for thread safety
        self.lock = threading.Lock()
    
    def process_csi_data(self, raw_data, timestamp, rssi, channel):
        """
        Process raw CSI data (I/Q pairs) into amplitude and phase.
        
        Args:
            raw_data: List of int8 values (interleaved I/Q)
            timestamp: ESP32 timestamp in microseconds
            rssi: Signal strength in dBm
            channel: WiFi channel number
        """
        with self.lock:
            self.packet_count += 1
            self.current_rssi = rssi
            self.current_channel = channel
            self.current_timestamp = timestamp
            
            # Convert raw data to numpy array
            data = np.array(raw_data, dtype=np.float32)
            
            # Extract I and Q components (interleaved)
            # CSI data format: [I0, Q0, I1, Q1, I2, Q2, ...]
            num_pairs = len(data) // 2
            if num_pairs > SUBCARRIER_COUNT:
                num_pairs = SUBCARRIER_COUNT
            
            if num_pairs > 0:
                i_vals = data[0:num_pairs*2:2]  # Even indices
                q_vals = data[1:num_pairs*2:2]  # Odd indices
                
                # Calculate amplitude: sqrt(I^2 + Q^2)
                amplitudes = np.sqrt(i_vals**2 + q_vals**2)
                
                # Calculate phase: atan2(Q, I)
                phases = np.arctan2(q_vals, i_vals)
                
                # Store current values (pad to SUBCARRIER_COUNT if needed)
                self.current_amplitudes[:num_pairs] = amplitudes
                self.current_phases[:num_pairs] = phases
                if num_pairs < SUBCARRIER_COUNT:
                    self.current_amplitudes[num_pairs:] = 0
                    self.current_phases[num_pairs:] = 0
                
                # Update time series
                elapsed_time = (timestamp - self.last_timestamp) / 1e6 if self.last_timestamp > 0 else 0
                self.last_timestamp = timestamp
                
                current_time = time.time() - self.start_time
                self.time_data.append(current_time)
                self.amplitude_history.append(np.mean(amplitudes))
                self.rssi_history.append(rssi)
                self.subcarrier_history.append(amplitudes.copy())
    
    def get_current_data(self):
        """Get current CSI data for plotting (thread-safe)."""
        with self.lock:
            return {
                'amplitudes': self.current_amplitudes.copy(),
                'phases': self.current_phases.copy(),
                'rssi': self.current_rssi,
                'channel': self.current_channel,
                'timestamp': self.current_timestamp,
                'time_data': list(self.time_data),
                'amplitude_history': list(self.amplitude_history),
                'rssi_history': list(self.rssi_history),
                'packet_count': self.packet_count,
                'subcarrier_history': list(self.subcarrier_history)
            }
    
    def get_stats(self):
        """Get statistics."""
        with self.lock:
            elapsed = time.time() - self.start_time
            rate = self.packet_count / elapsed if elapsed > 0 else 0
            return {
                'packet_count': self.packet_count,
                'elapsed_time': elapsed,
                'packets_per_second': rate
            }


# ============================================================================
# Packet Parsing
# ============================================================================

def unpack_packet(data):
    """Unpack ESP32 packet header."""
    if len(data) < PKT_HEADER_SIZE:
        return None
    
    magic, version, pkt_type = struct.unpack('>HBB', data[0:4])
    seq = struct.unpack('>I', data[4:8])[0]
    timestamp = struct.unpack('<Q', data[8:16])[0]
    payload_len = struct.unpack('>H', data[16:18])[0]
    
    if magic != PKT_MAGIC:
        return None
    
    payload = None
    if payload_len > 0 and len(data) >= PKT_HEADER_SIZE + payload_len:
        payload = data[PKT_HEADER_SIZE:PKT_HEADER_SIZE + payload_len]
    
    return {
        'type': pkt_type,
        'seq': seq,
        'timestamp': timestamp,
        'payload': payload
    }


def unpack_csi_payload(data):
    """Unpack CSI payload structure."""
    if len(data) < 11:  # Minimum: timestamp(8) + rssi(1) + channel(1) + len(1)
        return None
    
    timestamp = struct.unpack('<Q', data[0:8])[0]
    rssi = struct.unpack('b', data[8:9])[0]
    channel = struct.unpack('B', data[9:10])[0]
    data_len = struct.unpack('B', data[10:11])[0]
    
    actual_len = min(data_len, MAX_CSI_LEN, len(data) - 11)
    csi_data = [struct.unpack('b', data[11 + i:12 + i])[0] for i in range(actual_len)]
    
    return {
        'timestamp': timestamp,
        'rssi': rssi,
        'channel': channel,
        'len': data_len,
        'data': csi_data
    }


# ============================================================================
# UDP Receiver Thread
# ============================================================================

class CSIReceiver(threading.Thread):
    """Thread to receive CSI packets via UDP."""
    
    def __init__(self, port, processor, esp32_ip=None, verbose=False):
        super().__init__(daemon=True)
        self.port = port
        self.processor = processor
        self.esp32_ip = esp32_ip
        self.verbose = verbose
        self.running = True
        self.sock = None
        self.last_ping_time = 0
        self.PING_INTERVAL = 10  # Send PING every 10 seconds
    
    def run(self):
        """Main receive loop."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.settimeout(0.5)  # Timeout for clean shutdown
        
        # Send START command to ESP32 to begin CSI streaming
        if self.esp32_ip:
            print(f"Connecting to ESP32 at {self.esp32_ip}:{self.port}...")
            try:
                self.sock.sendto(b"START\n", (self.esp32_ip, self.port))
                # Wait briefly for acknowledgment
                try:
                    self.sock.settimeout(2.0)
                    ack, _ = self.sock.recvfrom(256)
                    print(f"ESP32: {ack.decode().strip()}")
                except socket.timeout:
                    print("No acknowledgment received, continuing...")
                self.sock.settimeout(0.5)
                self.last_ping_time = time.time()
            except Exception as e:
                print(f"Failed to send START: {e}")
        
        print(f"CSI Receiver started on port {self.port}")
        
        while self.running:
            try:
                # Send periodic PING to keep CSI stream alive
                if self.esp32_ip and (time.time() - self.last_ping_time) > self.PING_INTERVAL:
                    try:
                        self.sock.sendto(b"PING\n", (self.esp32_ip, self.port))
                        self.last_ping_time = time.time()
                    except:
                        pass
                
                data, addr = self.sock.recvfrom(2048)
                
                # Skip PONG responses
                if data.strip() == b"PONG":
                    continue
                
                packet = unpack_packet(data)
                if packet and packet['type'] == PKT_TYPE_CSI and packet['payload']:
                    csi = unpack_csi_payload(packet['payload'])
                    if csi and csi['data']:
                        self.processor.process_csi_data(
                            csi['data'],
                            csi['timestamp'],
                            csi['rssi'],
                            csi['channel']
                        )
                        
                        if self.verbose:
                            stats = self.processor.get_stats()
                            print(f"\r[{stats['packet_count']:5d}] "
                                  f"RSSI: {csi['rssi']:4d} dBm | "
                                  f"Ch: {csi['channel']:2d} | "
                                  f"Rate: {stats['packets_per_second']:.1f} pkt/s", end='')
                            
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"\nReceiver error: {e}")
        
        self.sock.close()
        print("\nCSI Receiver stopped")
    
    def stop(self):
        """Stop the receiver."""
        self.running = False
        # Send STOP command to ESP32
        if self.esp32_ip and self.sock:
            try:
                self.sock.sendto(b"STOP\n", (self.esp32_ip, self.port))
                print("\nSent STOP to ESP32")
            except:
                pass


class TrafficGenerator(threading.Thread):
    """Thread to generate WiFi traffic by sending packets to ESP32.
    
    CSI data is only captured when WiFi traffic occurs.
    This thread sends periodic UDP packets to ensure continuous CSI capture.
    """
    
    def __init__(self, target_ip, target_port=3333, interval_ms=50):
        super().__init__(daemon=True)
        self.target_ip = target_ip
        self.target_port = target_port
        self.interval = interval_ms / 1000.0  # Convert to seconds
        self.running = True
        self.packet_count = 0
    
    def run(self):
        """Main traffic generation loop."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        print(f"Traffic generator started: sending to {self.target_ip}:{self.target_port} "
              f"every {int(self.interval * 1000)}ms")
        
        ping_data = b'\xDE\xAD\xBE\xEF'  # Simple ping pattern
        
        while self.running:
            try:
                sock.sendto(ping_data, (self.target_ip, self.target_port))
                self.packet_count += 1
            except Exception as e:
                if self.packet_count % 100 == 0:
                    print(f"\nTraffic gen error: {e}")
            
            time.sleep(self.interval)
        
        sock.close()
        print(f"\nTraffic generator stopped (sent {self.packet_count} packets)")
    
    def stop(self):
        """Stop the traffic generator."""
        self.running = False


# ============================================================================
# Visualization
# ============================================================================

class CSIVisualizer:
    """Real-time CSI visualization using matplotlib."""
    
    def __init__(self, processor):
        self.processor = processor
        self.fig = None
        self.axes = {}
        self.lines = {}
        self.texts = {}
        
    def setup_plots(self):
        """Set up the matplotlib figure and axes."""
        # Create figure with custom layout
        self.fig = plt.figure(figsize=(14, 10))
        self.fig.suptitle('ESP32 CSI Real-Time Visualizer', fontsize=14, fontweight='bold')
        
        # Use GridSpec for flexible layout
        gs = GridSpec(3, 2, figure=self.fig, height_ratios=[1, 1, 0.8], hspace=0.3, wspace=0.25)
        
        # Plot 1: Amplitude vs Subcarrier (top-left)
        self.axes['subcarrier'] = self.fig.add_subplot(gs[0, 0])
        self.axes['subcarrier'].set_title('Amplitude vs Subcarrier (Current Frame)')
        self.axes['subcarrier'].set_xlabel('Subcarrier Index')
        self.axes['subcarrier'].set_ylabel('Amplitude')
        self.axes['subcarrier'].set_xlim(0, SUBCARRIER_COUNT)
        self.axes['subcarrier'].set_ylim(0, 200)
        self.axes['subcarrier'].grid(True, alpha=0.3)
        self.lines['subcarrier'], = self.axes['subcarrier'].plot([], [], 'b-', linewidth=1.5)
        self.lines['subcarrier_fill'] = self.axes['subcarrier'].fill_between(
            range(SUBCARRIER_COUNT), 0, np.zeros(SUBCARRIER_COUNT), alpha=0.3
        )
        
        # Plot 2: Phase vs Subcarrier (top-right)
        self.axes['phase'] = self.fig.add_subplot(gs[0, 1])
        self.axes['phase'].set_title('Phase vs Subcarrier (Current Frame)')
        self.axes['phase'].set_xlabel('Subcarrier Index')
        self.axes['phase'].set_ylabel('Phase (radians)')
        self.axes['phase'].set_xlim(0, SUBCARRIER_COUNT)
        self.axes['phase'].set_ylim(-np.pi, np.pi)
        self.axes['phase'].grid(True, alpha=0.3)
        self.lines['phase'], = self.axes['phase'].plot([], [], 'g-', linewidth=1.5)
        
        # Plot 3: Mean Amplitude vs Time (middle-left)
        self.axes['amplitude_time'] = self.fig.add_subplot(gs[1, 0])
        self.axes['amplitude_time'].set_title('Mean Amplitude vs Time (Motion Detection)')
        self.axes['amplitude_time'].set_xlabel('Time (seconds)')
        self.axes['amplitude_time'].set_ylabel('Mean Amplitude')
        self.axes['amplitude_time'].set_ylim(0, 100)
        self.axes['amplitude_time'].grid(True, alpha=0.3)
        self.lines['amplitude_time'], = self.axes['amplitude_time'].plot([], [], 'r-', linewidth=1.5)
        
        # Plot 4: RSSI vs Time (middle-right)
        self.axes['rssi_time'] = self.fig.add_subplot(gs[1, 1])
        self.axes['rssi_time'].set_title('RSSI vs Time')
        self.axes['rssi_time'].set_xlabel('Time (seconds)')
        self.axes['rssi_time'].set_ylabel('RSSI (dBm)')
        self.axes['rssi_time'].set_ylim(-100, 0)
        self.axes['rssi_time'].grid(True, alpha=0.3)
        self.lines['rssi_time'], = self.axes['rssi_time'].plot([], [], 'm-', linewidth=1.5)
        
        # Plot 5: CSI Heatmap over time (bottom, spans both columns)
        self.axes['heatmap'] = self.fig.add_subplot(gs[2, :])
        self.axes['heatmap'].set_title('CSI Amplitude Heatmap (Subcarriers vs Time)')
        self.axes['heatmap'].set_xlabel('Time Sample')
        self.axes['heatmap'].set_ylabel('Subcarrier Index')
        
        # Initialize heatmap with zeros
        self.heatmap_data = np.zeros((SUBCARRIER_COUNT, MAX_TIME_SAMPLES))
        self.lines['heatmap'] = self.axes['heatmap'].imshow(
            self.heatmap_data, 
            aspect='auto', 
            origin='lower',
            cmap='viridis',
            vmin=0, vmax=100
        )
        self.fig.colorbar(self.lines['heatmap'], ax=self.axes['heatmap'], label='Amplitude')
        
        # Stats text
        self.texts['stats'] = self.fig.text(
            0.02, 0.98, 
            'Packets: 0 | Rate: 0.0 pkt/s | RSSI: -- dBm | Channel: --',
            fontsize=10, verticalalignment='top',
            fontfamily='monospace',
            bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5)
        )
        
        plt.tight_layout(rect=[0, 0, 1, 0.96])
        
    def update(self, frame):
        """Update function for matplotlib animation."""
        data = self.processor.get_current_data()
        
        # Update subcarrier plot
        x = np.arange(SUBCARRIER_COUNT)
        self.lines['subcarrier'].set_data(x, data['amplitudes'])
        
        # Update fill_between (need to remove old and create new)
        self.lines['subcarrier_fill'].remove()
        self.lines['subcarrier_fill'] = self.axes['subcarrier'].fill_between(
            x, 0, data['amplitudes'], alpha=0.3, color='blue'
        )
        
        # Update phase plot
        self.lines['phase'].set_data(x, data['phases'])
        
        # Update amplitude vs time
        if len(data['time_data']) > 0:
            self.lines['amplitude_time'].set_data(data['time_data'], data['amplitude_history'])
            self.axes['amplitude_time'].set_xlim(
                max(0, data['time_data'][-1] - 10),
                max(10, data['time_data'][-1] + 1)
            )
            
            # Auto-adjust y-axis based on data
            if data['amplitude_history']:
                max_amp = max(data['amplitude_history']) * 1.2
                min_amp = min(data['amplitude_history']) * 0.8
                if max_amp > 0:
                    self.axes['amplitude_time'].set_ylim(max(0, min_amp), max_amp)
        
        # Update RSSI vs time
        if len(data['time_data']) > 0:
            self.lines['rssi_time'].set_data(data['time_data'], data['rssi_history'])
            self.axes['rssi_time'].set_xlim(
                max(0, data['time_data'][-1] - 10),
                max(10, data['time_data'][-1] + 1)
            )
        
        # Update heatmap
        if len(data['subcarrier_history']) > 0:
            # Convert to 2D array (subcarriers x time)
            history = data['subcarrier_history']
            num_samples = len(history)
            
            # Create heatmap data
            heatmap = np.zeros((SUBCARRIER_COUNT, MAX_TIME_SAMPLES))
            for i, amps in enumerate(history[-MAX_TIME_SAMPLES:]):
                col_idx = MAX_TIME_SAMPLES - num_samples + i
                if col_idx >= 0:
                    heatmap[:len(amps), col_idx] = amps
            
            self.lines['heatmap'].set_array(heatmap)
            
            # Auto-adjust color scale
            if np.max(heatmap) > 0:
                self.lines['heatmap'].set_clim(0, np.max(heatmap))
        
        # Update stats text
        stats = self.processor.get_stats()
        self.texts['stats'].set_text(
            f"Packets: {stats['packet_count']:d} | "
            f"Rate: {stats['packets_per_second']:.1f} pkt/s | "
            f"RSSI: {data['rssi']:d} dBm | "
            f"Channel: {data['channel']:d}"
        )
        
        return [self.lines['subcarrier'], self.lines['phase'], 
                self.lines['amplitude_time'], self.lines['rssi_time'],
                self.lines['heatmap'], self.texts['stats']]
    
    def run(self):
        """Start the visualization."""
        self.setup_plots()
        
        ani = animation.FuncAnimation(
            self.fig, 
            self.update, 
            interval=UPDATE_INTERVAL_MS,
            blit=False,  # Can't use blit with fill_between and imshow
            cache_frame_data=False
        )
        
        plt.show()


# ============================================================================
# Console-only mode
# ============================================================================

def run_console_mode(processor, receiver):
    """Run in console-only mode (no GUI)."""
    print("\nRunning in console mode. Press Ctrl+C to stop.\n")
    print("-" * 70)
    
    try:
        while True:
            time.sleep(1)
            stats = processor.get_stats()
            data = processor.get_current_data()
            
            print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                  f"Packets: {stats['packet_count']:5d} | "
                  f"Rate: {stats['packets_per_second']:5.1f} pkt/s | "
                  f"RSSI: {data['rssi']:4d} dBm | "
                  f"Channel: {data['channel']:2d} | "
                  f"Mean Amp: {np.mean(data['amplitudes']):6.1f}")
            
    except KeyboardInterrupt:
        print("\n\nStopping...")


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='ESP32 CSI Real-Time Visualizer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 csi_visualizer.py                          # Listen only (ESP32 generates traffic)
  python3 csi_visualizer.py --esp32 192.168.1.100    # Also generate traffic to ESP32
  python3 csi_visualizer.py --port 3334              # Specify listen port
  python3 csi_visualizer.py --no-plot                # Console-only mode (no matplotlib)
  python3 csi_visualizer.py --verbose                # Print each packet to console

Note: CSI is only captured when WiFi traffic occurs!
      Use --esp32 <IP> to generate traffic from this PC to the ESP32.
      The ESP32 also has a built-in traffic generator that sends to the gateway.

The visualizer shows:
  - Amplitude vs Subcarrier: Shows CSI amplitude across frequency subcarriers
  - Phase vs Subcarrier: Shows CSI phase across frequency subcarriers  
  - Amplitude vs Time: Shows mean amplitude over time (motion detection)
  - RSSI vs Time: Shows signal strength over time
  - Heatmap: Shows amplitude of all subcarriers over time
        """
    )
    parser.add_argument('--port', type=int, default=UDP_CSI_PORT,
                        help=f'UDP port to listen on (default: {UDP_CSI_PORT})')
    parser.add_argument('--esp32', type=str, default=None,
                        help='ESP32 IP address - enables traffic generation to ESP32')
    parser.add_argument('--traffic-interval', type=int, default=50,
                        help='Traffic generation interval in ms (default: 50)')
    parser.add_argument('--no-plot', action='store_true',
                        help='Run in console-only mode (no GUI)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Print packet info to console')
    
    args = parser.parse_args()
    
    # Check matplotlib availability
    use_gui = HAS_MATPLOTLIB and not args.no_plot
    
    if not use_gui and not args.no_plot:
        print("Note: Running without GUI (matplotlib not available)")
    
    # Create processor and receiver
    processor = CSIProcessor()
    receiver = CSIReceiver(args.port, processor, esp32_ip=args.esp32, 
                           verbose=args.verbose and not use_gui)
    
    # Create traffic generator if ESP32 IP provided (optional - ESP32 has built-in)
    traffic_gen = None
    if args.esp32 and args.traffic_interval > 0:
        traffic_gen = TrafficGenerator(args.esp32, 3333, args.traffic_interval)
    
    print(f"ESP32 CSI Visualizer")
    print(f"=" * 50)
    print(f"Listening on UDP port: {args.port}")
    if args.esp32:
        print(f"ESP32 IP: {args.esp32} (will send START command)")
    else:
        print(f"ESP32 IP: Not specified (use --esp32 <IP> to connect)")
    print(f"Mode: {'GUI visualization' if use_gui else 'Console only'}")
    if traffic_gen:
        print(f"Traffic gen: Sending to {args.esp32}:3333 every {args.traffic_interval}ms")
    else:
        print(f"Traffic gen: Using ESP32 built-in generator")
    print(f"=" * 50)
    
    # Start receiver thread
    receiver.start()
    
    # Start traffic generator if configured
    if traffic_gen:
        traffic_gen.start()
    
    try:
        if use_gui:
            visualizer = CSIVisualizer(processor)
            visualizer.run()
        else:
            run_console_mode(processor, receiver)
    except KeyboardInterrupt:
        pass
    finally:
        receiver.stop()
        receiver.join(timeout=2)
        
        if traffic_gen:
            traffic_gen.stop()
            traffic_gen.join(timeout=2)
        
        # Print final stats
        stats = processor.get_stats()
        print(f"\n{'=' * 50}")
        print(f"Final Statistics:")
        print(f"  Total packets: {stats['packet_count']}")
        print(f"  Runtime: {stats['elapsed_time']:.1f} seconds")
        print(f"  Average rate: {stats['packets_per_second']:.1f} packets/second")
        print(f"{'=' * 50}")


if __name__ == "__main__":
    main()

