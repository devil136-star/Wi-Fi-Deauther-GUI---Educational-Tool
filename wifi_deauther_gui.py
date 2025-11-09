#!/usr/bin/env python3
"""
Wi-Fi Deauther GUI - Educational Tool
======================================
A simple graphical user interface for the Wi-Fi Deauther tool.

⚠️  WARNING: This tool is for EDUCATIONAL PURPOSES ONLY.

Author: Himanshu Kumar
GitHub: https://github.com/devil136-star
LinkedIn: https://www.linkedin.com/in/himanshu-kumar-777a50292/
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import webbrowser
from wifi_deauther import WiFiDeauther

class WiFiDeautherGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Wi-Fi Deauther - Educational Tool")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        # Initialize deauther
        self.deauther = WiFiDeauther()
        
        # Warning label
        self.create_warning_frame()
        
        # Main notebook (tabs)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.create_scan_tab()
        self.create_deauth_tab()
        self.create_monitor_tab()
        self.create_info_tab()
        
        # Footer with author info
        self.create_footer()
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def create_warning_frame(self):
        """Create warning banner"""
        warning_frame = tk.Frame(self.root, bg="#ff6b6b", height=60)
        warning_frame.pack(fill=tk.X, padx=10, pady=(10, 0))
        warning_frame.pack_propagate(False)
        
        warning_label = tk.Label(
            warning_frame,
            text="⚠️  WARNING: EDUCATIONAL USE ONLY - Use responsibly and comply with applicable laws",
            bg="#ff6b6b",
            fg="white",
            font=("Arial", 10, "bold"),
            wraplength=800
        )
        warning_label.pack(expand=True)
    
    def create_footer(self):
        """Create footer with author information"""
        footer_frame = tk.Frame(self.root, bg="#f0f0f0", height=50)
        footer_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=(0, 5))
        footer_frame.pack_propagate(False)
        
        # Author name
        author_label = tk.Label(
            footer_frame,
            text="Developed by: Himanshu Kumar",
            bg="#f0f0f0",
            fg="#333333",
            font=("Arial", 9, "bold")
        )
        author_label.pack(side=tk.LEFT, padx=10, pady=5)
        
        # Separator
        separator1 = tk.Label(
            footer_frame,
            text="|",
            bg="#f0f0f0",
            fg="#999999",
            font=("Arial", 9)
        )
        separator1.pack(side=tk.LEFT, padx=5)
        
        # GitHub link
        github_label = tk.Label(
            footer_frame,
            text="GitHub: devil136-star",
            bg="#f0f0f0",
            fg="#0066cc",
            font=("Arial", 8),
            cursor="hand2"
        )
        github_label.pack(side=tk.LEFT, padx=5, pady=5)
        github_label.bind("<Button-1>", lambda e: self.open_url("https://github.com/devil136-star"))
        
        # Separator
        separator2 = tk.Label(
            footer_frame,
            text="|",
            bg="#f0f0f0",
            fg="#999999",
            font=("Arial", 9)
        )
        separator2.pack(side=tk.LEFT, padx=5)
        
        # LinkedIn link
        linkedin_label = tk.Label(
            footer_frame,
            text="LinkedIn: himanshu-kumar-777a50292",
            bg="#f0f0f0",
            fg="#0066cc",
            font=("Arial", 8),
            cursor="hand2"
        )
        linkedin_label.pack(side=tk.LEFT, padx=5, pady=5)
        linkedin_label.bind("<Button-1>", lambda e: self.open_url("https://www.linkedin.com/in/himanshu-kumar-777a50292/"))
    
    def open_url(self, url):
        """Open URL in default browser"""
        webbrowser.open(url)
    
    def create_scan_tab(self):
        """Create network scanning tab"""
        scan_frame = ttk.Frame(self.notebook)
        self.notebook.add(scan_frame, text="📡 Network Scanner")
        
        # Controls
        control_frame = ttk.LabelFrame(scan_frame, text="Scan Controls", padding=10)
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(control_frame, text="Duration (seconds):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.scan_duration = tk.StringVar(value="10")
        ttk.Entry(control_frame, textvariable=self.scan_duration, width=10).grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(control_frame, text="Interface:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.scan_interface = ttk.Combobox(control_frame, width=20, state="readonly")
        self.scan_interface.grid(row=0, column=3, padx=5, pady=5)
        self.update_interfaces()
        
        self.scan_button = ttk.Button(control_frame, text="🔍 Start Scan", command=self.start_scan)
        self.scan_button.grid(row=0, column=4, padx=10, pady=5)
        
        # Results
        results_frame = ttk.LabelFrame(scan_frame, text="Scan Results", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Treeview for networks
        columns = ("SSID", "BSSID", "Signal", "Channel", "Encryption")
        self.network_tree = ttk.Treeview(results_frame, columns=columns, show="headings", height=15)
        
        for col in columns:
            self.network_tree.heading(col, text=col)
            self.network_tree.column(col, width=150)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.network_tree.yview)
        self.network_tree.configure(yscrollcommand=scrollbar.set)
        
        self.network_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_deauth_tab(self):
        """Create deauthentication tab"""
        deauth_frame = ttk.Frame(self.notebook)
        self.notebook.add(deauth_frame, text="⚡ Deauthentication")
        
        # Warning
        warning_label = tk.Label(
            deauth_frame,
            text="⚠️  This will disconnect devices from networks. Use only on networks you own!",
            fg="red",
            font=("Arial", 9, "bold"),
            wraplength=800
        )
        warning_label.pack(pady=10)
        
        # Controls
        control_frame = ttk.LabelFrame(deauth_frame, text="Deauthentication Controls", padding=10)
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(control_frame, text="Select Network:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.deauth_network = ttk.Combobox(control_frame, width=40, state="readonly")
        self.deauth_network.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W+tk.E)
        
        ttk.Label(control_frame, text="Client MAC (optional):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.client_mac = ttk.Entry(control_frame, width=40)
        self.client_mac.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W+tk.E)
        ttk.Label(control_frame, text="(Leave empty for broadcast)").grid(row=1, column=2, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(control_frame, text="Packets to send:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.deauth_count = tk.StringVar(value="10")
        ttk.Entry(control_frame, textvariable=self.deauth_count, width=10).grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(control_frame, text="Interface:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.deauth_interface = ttk.Combobox(control_frame, width=20, state="readonly")
        self.deauth_interface.grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)
        self.update_deauth_interfaces()
        
        self.deauth_button = ttk.Button(control_frame, text="⚡ Start Deauthentication", command=self.start_deauth)
        self.deauth_button.grid(row=4, column=1, padx=5, pady=10)
        
        # Log
        log_frame = ttk.LabelFrame(deauth_frame, text="Activity Log", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.deauth_log = scrolledtext.ScrolledText(log_frame, height=15, wrap=tk.WORD)
        self.deauth_log.pack(fill=tk.BOTH, expand=True)
    
    def create_monitor_tab(self):
        """Create network monitoring tab"""
        monitor_frame = ttk.Frame(self.notebook)
        self.notebook.add(monitor_frame, text="📊 Network Monitor")
        
        # Controls
        control_frame = ttk.LabelFrame(monitor_frame, text="Monitoring Controls", padding=10)
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(control_frame, text="Select Network:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.monitor_network = ttk.Combobox(control_frame, width=40, state="readonly")
        self.monitor_network.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W+tk.E)
        
        ttk.Label(control_frame, text="Duration (seconds):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.monitor_duration = tk.StringVar(value="30")
        ttk.Entry(control_frame, textvariable=self.monitor_duration, width=10).grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(control_frame, text="Interface:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.monitor_interface = ttk.Combobox(control_frame, width=20, state="readonly")
        self.monitor_interface.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        self.update_monitor_interfaces()
        
        self.monitor_button = ttk.Button(control_frame, text="📊 Start Monitoring", command=self.start_monitor)
        self.monitor_button.grid(row=3, column=1, padx=5, pady=10)
        
        # Log
        log_frame = ttk.LabelFrame(monitor_frame, text="Monitoring Log", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.monitor_log = scrolledtext.ScrolledText(log_frame, height=15, wrap=tk.WORD)
        self.monitor_log.pack(fill=tk.BOTH, expand=True)
    
    def create_info_tab(self):
        """Create information tab"""
        info_frame = ttk.Frame(self.notebook)
        self.notebook.add(info_frame, text="ℹ️  Information")
        
        info_text = scrolledtext.ScrolledText(info_frame, wrap=tk.WORD, padx=10, pady=10)
        info_text.pack(fill=tk.BOTH, expand=True)
        
        info_content = """
╔══════════════════════════════════════════════════════════════════════════╗
║                    WI-FI DEAUTHER - EDUCATIONAL TOOL                      ║
╚══════════════════════════════════════════════════════════════════════════╝

⚠️  WARNING: EDUCATIONAL USE ONLY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

This tool is designed for educational purposes only. Unauthorized access to 
computer networks is ILLEGAL in many jurisdictions.

✅ LEGAL USES:
  • Testing your own networks
  • Authorized penetration testing
  • Educational learning and research
  • Security auditing with permission

❌ ILLEGAL USES:
  • Attacking networks without permission
  • Disrupting public or private networks
  • Unauthorized access attempts
  • Any malicious activity

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

HOW TO USE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. NETWORK SCANNER:
   • Select scan duration (default: 10 seconds)
   • Choose network interface (optional)
   • Click "Start Scan" to discover Wi-Fi networks
   • Results will appear in the table below

2. DEAUTHENTICATION:
   • First, scan for networks
   • Select a network from the dropdown
   • Optionally specify a client MAC address
   • Set number of packets to send
   • Click "Start Deauthentication"
   ⚠️  WARNING: This will disconnect devices!

3. NETWORK MONITOR:
   • Select a network to monitor
   • Set monitoring duration
   • Click "Start Monitoring"
   • View captured packets in the log

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

REQUIREMENTS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

• Python 3.7+
• Administrator/Root privileges
• Wireless adapter with monitor mode support
• Windows: Npcap or WinPcap installed
• Linux: Wireless tools installed

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

TROUBLESHOOTING:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

• "No networks found": Check interface selection and permissions
• "Permission denied": Run with administrator/root privileges
• "Interface not found": Verify wireless adapter is connected

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

AUTHOR:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Himanshu Kumar
• GitHub: https://github.com/devil136-star
• LinkedIn: https://www.linkedin.com/in/himanshu-kumar-777a50292/

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Stay Legal. Stay Ethical. Stay Safe.
        """
        
        info_text.insert(tk.END, info_content)
        info_text.config(state=tk.DISABLED)
    
    def update_interfaces(self):
        """Update interface dropdowns"""
        interfaces = self.deauther.get_interfaces()
        if interfaces:
            self.scan_interface['values'] = [''] + interfaces
            self.scan_interface.set('')
        else:
            self.scan_interface['values'] = ['']
    
    def update_deauth_interfaces(self):
        """Update deauth interface dropdown"""
        interfaces = self.deauther.get_interfaces()
        if interfaces:
            self.deauth_interface['values'] = [''] + interfaces
            self.deauth_interface.set('')
        else:
            self.deauth_interface['values'] = ['']
    
    def update_monitor_interfaces(self):
        """Update monitor interface dropdown"""
        interfaces = self.deauther.get_interfaces()
        if interfaces:
            self.monitor_interface['values'] = [''] + interfaces
            self.monitor_interface.set('')
        else:
            self.monitor_interface['values'] = ['']
    
    def update_network_dropdowns(self):
        """Update network selection dropdowns"""
        networks = [f"{net['ssid']} ({net['bssid']})" for net in self.deauther.networks]
        self.deauth_network['values'] = networks
        self.monitor_network['values'] = networks
        if networks:
            self.deauth_network.set('')
            self.monitor_network.set('')
    
    def start_scan(self):
        """Start network scanning in a separate thread"""
        def scan_thread():
            self.scan_button.config(state=tk.DISABLED)
            self.status_var.set("Scanning...")
            
            # Clear previous results
            for item in self.network_tree.get_children():
                self.network_tree.delete(item)
            
            duration = int(self.scan_duration.get()) if self.scan_duration.get().isdigit() else 10
            interface = self.scan_interface.get() if self.scan_interface.get() else None
            
            try:
                networks = self.deauther.scan_networks(interface=interface, duration=duration)
                
                # Update treeview
                for network in networks:
                    self.network_tree.insert('', tk.END, values=(
                        network['ssid'],
                        network['bssid'],
                        f"{network['signal']} dBm" if network['signal'] else "N/A",
                        network['channel'],
                        network['encryption']
                    ))
                
                self.update_network_dropdowns()
                self.status_var.set(f"Scan complete: Found {len(networks)} networks")
                messagebox.showinfo("Scan Complete", f"Found {len(networks)} network(s)")
            except Exception as e:
                self.status_var.set(f"Error: {str(e)}")
                messagebox.showerror("Error", f"Scan failed: {str(e)}")
            finally:
                self.scan_button.config(state=tk.NORMAL)
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def start_deauth(self):
        """Start deauthentication attack"""
        if not self.deauther.networks:
            messagebox.showwarning("No Networks", "Please scan for networks first!")
            return
        
        network_str = self.deauth_network.get()
        if not network_str:
            messagebox.showwarning("No Network", "Please select a network!")
            return
        
        # Extract BSSID from selection
        bssid = network_str.split('(')[1].split(')')[0] if '(' in network_str else None
        if not bssid:
            messagebox.showerror("Error", "Invalid network selection")
            return
        
        # Confirmation
        if not messagebox.askyesno("Confirm", "⚠️  This will disconnect devices from the network!\n\nContinue?"):
            return
        
        def deauth_thread():
            self.deauth_button.config(state=tk.DISABLED)
            self.status_var.set("Deauthenticating...")
            
            client_mac = self.client_mac.get().strip() if self.client_mac.get().strip() else None
            count = int(self.deauth_count.get()) if self.deauth_count.get().isdigit() else 10
            interface = self.deauth_interface.get() if self.deauth_interface.get() else None
            
            self.deauth_log.insert(tk.END, f"Starting deauthentication attack...\n")
            self.deauth_log.insert(tk.END, f"Target: {network_str}\n")
            self.deauth_log.insert(tk.END, f"Packets: {count}\n\n")
            self.deauth_log.see(tk.END)
            
            try:
                self.deauther.deauthenticate(bssid, client_mac=client_mac, interface=interface, count=count)
                self.deauth_log.insert(tk.END, f"\n✅ Attack completed successfully\n")
                self.status_var.set("Deauthentication complete")
                messagebox.showinfo("Complete", "Deauthentication attack completed")
            except Exception as e:
                self.deauth_log.insert(tk.END, f"\n❌ Error: {str(e)}\n")
                self.status_var.set(f"Error: {str(e)}")
                messagebox.showerror("Error", f"Attack failed: {str(e)}")
            finally:
                self.deauth_button.config(state=tk.NORMAL)
                self.deauth_log.see(tk.END)
        
        threading.Thread(target=deauth_thread, daemon=True).start()
    
    def start_monitor(self):
        """Start network monitoring"""
        if not self.deauther.networks:
            messagebox.showwarning("No Networks", "Please scan for networks first!")
            return
        
        network_str = self.monitor_network.get()
        if not network_str:
            messagebox.showwarning("No Network", "Please select a network!")
            return
        
        # Extract BSSID
        bssid = network_str.split('(')[1].split(')')[0] if '(' in network_str else None
        if not bssid:
            messagebox.showerror("Error", "Invalid network selection")
            return
        
        def monitor_thread():
            self.monitor_button.config(state=tk.DISABLED)
            self.status_var.set("Monitoring...")
            
            duration = int(self.monitor_duration.get()) if self.monitor_duration.get().isdigit() else 30
            interface = self.monitor_interface.get() if self.monitor_interface.get() else None
            
            self.monitor_log.insert(tk.END, f"Starting network monitoring...\n")
            self.monitor_log.insert(tk.END, f"Target: {network_str}\n")
            self.monitor_log.insert(tk.END, f"Duration: {duration} seconds\n\n")
            self.monitor_log.see(tk.END)
            
            try:
                # Custom monitoring with log updates
                from scapy.all import sniff, Dot11
                from collections import defaultdict
                import time
                
                packet_count = defaultdict(int)
                start_time = time.time()
                
                def packet_handler(pkt):
                    if pkt.haslayer(Dot11):
                        if pkt.addr2 == bssid or pkt.addr3 == bssid:
                            packet_type = pkt.type
                            packet_subtype = pkt.subtype
                            packet_count[(packet_type, packet_subtype)] += 1
                            
                            src = pkt.addr2
                            dst = pkt.addr3
                            log_msg = f"📦 Type: {packet_type}, Subtype: {packet_subtype} | From: {src} → To: {dst}\n"
                            self.monitor_log.insert(tk.END, log_msg)
                            self.monitor_log.see(tk.END)
                
                if interface:
                    sniff(iface=interface, prn=packet_handler, timeout=duration)
                else:
                    sniff(prn=packet_handler, timeout=duration)
                
                elapsed = time.time() - start_time
                self.monitor_log.insert(tk.END, f"\n📊 Monitoring Summary ({elapsed:.1f} seconds):\n")
                self.monitor_log.insert(tk.END, "-" * 60 + "\n")
                for (ptype, psubtype), count in packet_count.items():
                    self.monitor_log.insert(tk.END, f"  Type {ptype}, Subtype {psubtype}: {count} packets\n")
                self.monitor_log.insert(tk.END, "-" * 60 + "\n")
                
                self.status_var.set("Monitoring complete")
                messagebox.showinfo("Complete", "Network monitoring completed")
            except KeyboardInterrupt:
                self.monitor_log.insert(tk.END, "\n⏹️  Monitoring stopped by user\n")
            except Exception as e:
                self.monitor_log.insert(tk.END, f"\n❌ Error: {str(e)}\n")
                self.status_var.set(f"Error: {str(e)}")
                messagebox.showerror("Error", f"Monitoring failed: {str(e)}")
            finally:
                self.monitor_button.config(state=tk.NORMAL)
                self.monitor_log.see(tk.END)
        
        threading.Thread(target=monitor_thread, daemon=True).start()


def main():
    root = tk.Tk()
    app = WiFiDeautherGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

