#!/usr/bin/env python3
"""
ESP32 WiFi Provisioning Client

This script connects to the ESP32 in provisioning mode and allows you to:
1. Scan for available WiFi networks
2. Connect the ESP32 to a selected network
3. Check connection status
4. Reset stored credentials

Usage:
    python3 wifi_provision.py [ESP32_IP] [--port PORT]
    
Default ESP32 IP: 192.168.4.1 (ESP32 AP mode default)
Default TCP port: 8080

Example:
    # Connect to ESP32 AP first, then run:
    python3 wifi_provision.py
    
    # Or specify IP if different:
    python3 wifi_provision.py 192.168.4.1 --port 8080
"""

import socket
import sys
import argparse
import time
from typing import List, Tuple, Optional


# Default configuration
DEFAULT_ESP32_IP = "192.168.4.1"
DEFAULT_TCP_PORT = 8080
SOCKET_TIMEOUT = 10.0


class ESP32Provisioner:
    """Client for ESP32 WiFi provisioning over TCP."""
    
    def __init__(self, host: str, port: int):
        """
        Initialize the provisioner.
        
        Args:
            host: ESP32 IP address
            port: TCP port for provisioning server
        """
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None
    
    def connect(self) -> bool:
        """
        Connect to the ESP32 provisioning server.
        
        Returns:
            True if connected successfully, False otherwise
        """
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(SOCKET_TIMEOUT)
            self.sock.connect((self.host, self.port))
            
            # Read welcome message
            welcome = self._recv_response()
            print(f"Connected to ESP32 at {self.host}:{self.port}")
            print(f"Server: {welcome.strip()}")
            return True
            
        except socket.timeout:
            print(f"Error: Connection timed out connecting to {self.host}:{self.port}")
            return False
        except socket.error as e:
            print(f"Error: Failed to connect to {self.host}:{self.port}: {e}")
            return False
    
    def disconnect(self):
        """Close the connection to ESP32."""
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None
    
    def _send_command(self, command: str) -> str:
        """
        Send a command and receive response.
        
        Args:
            command: Command string to send
            
        Returns:
            Response string from ESP32
        """
        if not self.sock:
            raise RuntimeError("Not connected")
        
        self.sock.sendall((command + "\n").encode('utf-8'))
        return self._recv_response()
    
    def _recv_response(self) -> str:
        """
        Receive response from ESP32.
        
        Returns:
            Response string
        """
        if not self.sock:
            raise RuntimeError("Not connected")
        
        response = b""
        self.sock.settimeout(SOCKET_TIMEOUT)
        
        try:
            while True:
                chunk = self.sock.recv(1024)
                if not chunk:
                    break
                response += chunk
                # Check if we have a complete response (ends with newline)
                if response.endswith(b"\n"):
                    break
        except socket.timeout:
            pass
        
        return response.decode('utf-8', errors='replace')
    
    def scan_networks(self) -> List[Tuple[str, int, str]]:
        """
        Scan for available WiFi networks.
        
        Returns:
            List of tuples: (ssid, rssi, auth_mode)
        """
        response = self._send_command("SCAN")
        lines = response.strip().split('\n')
        
        networks = []
        
        if lines and lines[0].startswith("OK"):
            # Parse "OK count"
            try:
                count = int(lines[0].split()[1])
            except (IndexError, ValueError):
                count = 0
            
            # Parse network entries
            for line in lines[1:]:
                parts = line.strip().split(',')
                if len(parts) >= 3:
                    ssid = parts[0]
                    try:
                        rssi = int(parts[1])
                    except ValueError:
                        rssi = -100
                    auth = parts[2]
                    networks.append((ssid, rssi, auth))
        else:
            print(f"Scan error: {response}")
        
        return networks
    
    def connect_wifi(self, ssid: str, password: str = "") -> Tuple[bool, str]:
        """
        Connect ESP32 to a WiFi network.
        
        Args:
            ssid: Network SSID (can contain spaces)
            password: Network password (empty for open networks)
            
        Returns:
            Tuple of (success, message)
        """
        # Use comma as delimiter to support SSIDs with spaces
        command = f"CONNECT {ssid},{password}" if password else f"CONNECT {ssid}"
        response = self._send_command(command)
        
        if response.startswith("OK Connected"):
            # Extract IP address if present
            parts = response.strip().split()
            ip = parts[2] if len(parts) > 2 else "unknown"
            return True, f"Connected! IP: {ip}"
        else:
            return False, response.strip()
    
    def get_status(self) -> str:
        """
        Get current connection status.
        
        Returns:
            Status string
        """
        response = self._send_command("STATUS")
        return response.strip()
    
    def reset_credentials(self) -> bool:
        """
        Clear stored WiFi credentials and reboot ESP32.
        
        Returns:
            True if command was acknowledged
        """
        response = self._send_command("RESET")
        return response.startswith("OK")
    
    def reprovision(self) -> bool:
        """
        Restart ESP32 in provisioning mode (keeps credentials).
        
        Returns:
            True if command was acknowledged
        """
        response = self._send_command("REPROVISION")
        return response.startswith("OK")
    
    def reboot(self) -> bool:
        """
        Reboot the ESP32.
        
        Returns:
            True if command was acknowledged
        """
        response = self._send_command("REBOOT")
        return response.startswith("OK")
    
    def get_ssid(self) -> str:
        """
        Get currently connected SSID.
        
        Returns:
            SSID string or error message
        """
        response = self._send_command("SSID")
        if response.startswith("OK "):
            return response[3:].strip()
        return response.strip()
    
    def get_help(self) -> str:
        """
        Get available commands from server.
        
        Returns:
            Help text
        """
        response = self._send_command("HELP")
        return response.strip()


def rssi_to_bars(rssi: int) -> str:
    """Convert RSSI to signal strength bars."""
    if rssi > -50:
        return "▂▄▆█"
    elif rssi > -60:
        return "▂▄▆ "
    elif rssi > -70:
        return "▂▄  "
    else:
        return "▂   "


def interactive_mode(provisioner: ESP32Provisioner):
    """Run interactive provisioning session."""
    
    print("\n" + "="*60)
    print("ESP32 WiFi Provisioning")
    print("="*60)
    
    while True:
        print("\nOptions:")
        print("  1. Scan for WiFi networks")
        print("  2. Connect to a network")
        print("  3. Check connection status")
        print("  4. Reset credentials and reboot")
        print("  5. Exit")
        print()
        
        try:
            choice = input("Select option (1-5): ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting...")
            break
        
        if choice == "1":
            print("\nScanning for networks...")
            networks = provisioner.scan_networks()
            
            if not networks:
                print("No networks found or scan failed.")
                continue
            
            print(f"\nFound {len(networks)} networks:\n")
            print(f"{'#':<4} {'SSID':<32} {'Signal':<6} {'Security':<10}")
            print("-" * 56)
            
            for i, (ssid, rssi, auth) in enumerate(networks, 1):
                bars = rssi_to_bars(rssi)
                print(f"{i:<4} {ssid:<32} {bars:<6} {auth:<10}")
            
        elif choice == "2":
            # First scan if not done
            print("\nScanning for networks...")
            networks = provisioner.scan_networks()
            
            if not networks:
                print("No networks found. Please try again.")
                continue
            
            print(f"\nAvailable networks:")
            for i, (ssid, rssi, auth) in enumerate(networks, 1):
                bars = rssi_to_bars(rssi)
                print(f"  {i}. {ssid} ({bars}) - {auth}")
            
            try:
                selection = input("\nEnter network number (or SSID): ").strip()
                
                # Try to parse as number
                try:
                    idx = int(selection) - 1
                    if 0 <= idx < len(networks):
                        ssid = networks[idx][0]
                        auth = networks[idx][2]
                    else:
                        print("Invalid selection.")
                        continue
                except ValueError:
                    # Treat as SSID
                    ssid = selection
                    auth = "Secured"  # Assume secured
                
                # Get password if secured
                if auth != "Open":
                    password = input(f"Enter password for '{ssid}': ").strip()
                else:
                    password = ""
                
                print(f"\nConnecting to '{ssid}'...")
                success, message = provisioner.connect_wifi(ssid, password)
                
                if success:
                    print(f"✓ {message}")
                    print("\nESP32 is now connected to your network!")
                    print("The provisioning server will stop and CSI streaming will start.")
                    print("Exiting provisioning client...")
                    break
                else:
                    print(f"✗ Connection failed: {message}")
                    
            except (KeyboardInterrupt, EOFError):
                print("\nCancelled.")
                continue
            
        elif choice == "3":
            status = provisioner.get_status()
            print(f"\nStatus: {status}")
            
        elif choice == "4":
            confirm = input("\nThis will clear saved credentials and reboot. Continue? (y/N): ")
            if confirm.lower() == 'y':
                print("Resetting...")
                if provisioner.reset_credentials():
                    print("ESP32 is rebooting. Credentials cleared.")
                    break
                else:
                    print("Reset command failed.")
            else:
                print("Cancelled.")
                
        elif choice == "5":
            print("Exiting...")
            break
        
        else:
            print("Invalid option. Please enter 1-5.")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="ESP32 WiFi Provisioning and Control Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Provisioning mode (connect to ESP32_CSI_Setup AP first):
    %(prog)s                      # Connect to default 192.168.4.1:8080
    %(prog)s --scan               # Just scan and display networks
    %(prog)s --connect "MyWiFi" "password123"  # Non-interactive connect
  
  Control mode (ESP32 connected to your network):
    %(prog)s 192.168.1.100 --status    # Check status on STA IP
    %(prog)s 192.168.1.100 --reset     # Reset credentials remotely
    %(prog)s 192.168.1.100 --reprovision  # Restart in provisioning mode
"""
    )
    
    parser.add_argument("host", nargs="?", default=DEFAULT_ESP32_IP,
                        help=f"ESP32 IP address (default: {DEFAULT_ESP32_IP})")
    parser.add_argument("--port", "-p", type=int, default=DEFAULT_TCP_PORT,
                        help=f"TCP port (default: {DEFAULT_TCP_PORT})")
    parser.add_argument("--scan", "-s", action="store_true",
                        help="Scan for networks and exit (provisioning mode)")
    parser.add_argument("--connect", "-c", nargs=2, metavar=("SSID", "PASSWORD"),
                        help="Connect to network (provisioning mode)")
    parser.add_argument("--status", action="store_true",
                        help="Check connection status and exit")
    parser.add_argument("--reset", action="store_true",
                        help="Reset credentials and reboot ESP32")
    parser.add_argument("--reprovision", action="store_true",
                        help="Restart ESP32 in provisioning mode (keeps credentials)")
    parser.add_argument("--reboot", action="store_true",
                        help="Reboot the ESP32")
    
    args = parser.parse_args()
    
    # Create provisioner and connect
    provisioner = ESP32Provisioner(args.host, args.port)
    
    print(f"Connecting to ESP32 at {args.host}:{args.port}...")
    
    # Show appropriate hint based on IP address
    if args.host == DEFAULT_ESP32_IP:
        print("(Make sure you're connected to the ESP32_CSI_Setup WiFi network)\n")
    else:
        print("(Connecting to ESP32 on your network)\n")
    
    if not provisioner.connect():
        print("\nFailed to connect to ESP32.")
        print("Make sure:")
        if args.host == DEFAULT_ESP32_IP:
            print("  1. You're connected to the ESP32_CSI_Setup WiFi network")
            print("  2. The ESP32 is in provisioning mode")
        else:
            print("  1. The ESP32 is connected to your network")
            print("  2. The ESP32 control server is running")
        print(f"  3. The IP address {args.host} is correct")
        sys.exit(1)
    
    try:
        if args.scan:
            # Just scan and exit
            networks = provisioner.scan_networks()
            print(f"\nFound {len(networks)} networks:\n")
            for ssid, rssi, auth in networks:
                print(f"  {ssid} (RSSI: {rssi} dBm, {auth})")
                
        elif args.connect:
            # Non-interactive connect
            ssid, password = args.connect
            print(f"Connecting to '{ssid}'...")
            success, message = provisioner.connect_wifi(ssid, password)
            if success:
                print(f"Success: {message}")
            else:
                print(f"Failed: {message}")
                sys.exit(1)
                
        elif args.status:
            # Check status
            status = provisioner.get_status()
            print(f"Status: {status}")
            
        elif args.reset:
            # Reset credentials
            print("Resetting credentials...")
            if provisioner.reset_credentials():
                print("ESP32 is rebooting with credentials cleared.")
            else:
                print("Reset failed.")
                sys.exit(1)
                
        elif args.reprovision:
            # Restart in provisioning mode
            print("Requesting provisioning mode restart...")
            if provisioner.reprovision():
                print("ESP32 is restarting in provisioning mode.")
                print("Connect to the ESP32_CSI_Setup WiFi network to configure.")
            else:
                print("Reprovision request failed.")
                sys.exit(1)
                
        elif args.reboot:
            # Reboot the device
            print("Rebooting ESP32...")
            if provisioner.reboot():
                print("ESP32 is rebooting.")
            else:
                print("Reboot request failed.")
                sys.exit(1)
                
        else:
            # Interactive mode
            interactive_mode(provisioner)
            
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)
    finally:
        provisioner.disconnect()


if __name__ == "__main__":
    main()

