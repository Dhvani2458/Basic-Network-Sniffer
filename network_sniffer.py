import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import socket
import struct
import textwrap
import time
import os
from datetime import datetime

class NetworkSniffer:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Sniffer")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        
        self.capture_active = False
        self.captured_packets = []
        self.packet_count = 0
        self.filter_text = ""
        self.selected_interface = None
        self.interfaces = self.get_network_interfaces()
        
        self.setup_ui()
    
    def get_network_interfaces(self):
        # This is a simplified approach - for a real application you'd use
        # platform-specific methods to get actual interfaces
        if os.name == 'nt':  # Windows
            return ['eth0', 'wlan0', 'lo']
        else:  # Linux/Mac
            return ['eth0', 'wlan0', 'lo']
    
    def setup_ui(self):
        # Create main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Control panel frame
        control_frame = ttk.LabelFrame(main_frame, text="Controls", padding="10")
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Interface selection
        ttk.Label(control_frame, text="Interface:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(control_frame, textvariable=self.interface_var, values=self.interfaces, width=15)
        self.interface_combo.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        self.interface_combo.current(0)
        
        # Filter
        ttk.Label(control_frame, text="Filter:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        self.filter_var = tk.StringVar()
        filter_entry = ttk.Entry(control_frame, textvariable=self.filter_var, width=30)
        filter_entry.grid(row=0, column=3, sticky=tk.W, padx=5, pady=5)
        
        # Buttons
        btn_frame = ttk.Frame(control_frame)
        btn_frame.grid(row=0, column=4, padx=5, pady=5)
        
        self.start_btn = ttk.Button(btn_frame, text="Start Capture", command=self.start_capture)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(btn_frame, text="Stop Capture", command=self.stop_capture, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text="Clear", command=self.clear_display).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Save", command=self.save_capture).pack(side=tk.LEFT, padx=5)
        
        # Statistics frame
        stats_frame = ttk.LabelFrame(main_frame, text="Statistics", padding="10")
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.stats_var = tk.StringVar(value="Packets: 0 | TCP: 0 | UDP: 0 | ICMP: 0 | Other: 0")
        ttk.Label(stats_frame, textvariable=self.stats_var, font=("TkDefaultFont", 10)).pack(fill=tk.X)
        
        # Create notebook (tabs)
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Packet list tab
        packet_frame = ttk.Frame(notebook)
        notebook.add(packet_frame, text="Packet List")
        
        # Setup treeview for packet list
        columns = ('No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info')
        self.packet_tree = ttk.Treeview(packet_frame, columns=columns, show='headings')
        
        # Define column headings
        for col in columns:
            self.packet_tree.heading(col, text=col)
            width = 100 if col != 'Info' else 300
            self.packet_tree.column(col, width=width)
        
        # Add scrollbars to the treeview
        y_scrollbar = ttk.Scrollbar(packet_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=y_scrollbar.set)
        
        x_scrollbar = ttk.Scrollbar(packet_frame, orient=tk.HORIZONTAL, command=self.packet_tree.xview)
        self.packet_tree.configure(xscrollcommand=x_scrollbar.set)
        
        # Grid layout for treeview and scrollbars
        self.packet_tree.grid(row=0, column=0, sticky='nsew')
        y_scrollbar.grid(row=0, column=1, sticky='ns')
        x_scrollbar.grid(row=1, column=0, sticky='ew')
        
        packet_frame.grid_rowconfigure(0, weight=1)
        packet_frame.grid_columnconfigure(0, weight=1)
        
        # Bind select event
        self.packet_tree.bind('<<TreeviewSelect>>', self.on_packet_select)
        
        # Packet details tab
        details_frame = ttk.Frame(notebook)
        notebook.add(details_frame, text="Packet Details")
        
        self.details_text = scrolledtext.ScrolledText(details_frame, wrap=tk.WORD, width=80, height=20)
        self.details_text.pack(fill=tk.BOTH, expand=True)
        
        # Raw data tab
        raw_frame = ttk.Frame(notebook)
        notebook.add(raw_frame, text="Raw Data")
        
        self.raw_text = scrolledtext.ScrolledText(raw_frame, wrap=tk.WORD, width=80, height=20, font=('Courier', 10))
        self.raw_text.pack(fill=tk.BOTH, expand=True)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def start_capture(self):
        if not self.capture_active:
            self.selected_interface = self.interface_var.get()
            self.filter_text = self.filter_var.get()
            
            if not self.selected_interface:
                messagebox.showerror("Error", "Please select a network interface")
                return
            
            self.capture_active = True
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.status_var.set(f"Capturing on {self.selected_interface}...")
            
            # Start capture in a separate thread
            self.capture_thread = threading.Thread(target=self.capture_packets)
            self.capture_thread.daemon = True
            self.capture_thread.start()
    
    def stop_capture(self):
        if self.capture_active:
            self.capture_active = False
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.status_var.set("Capture stopped")
    
    def clear_display(self):
        self.packet_tree.delete(*self.packet_tree.get_children())
        self.details_text.delete(1.0, tk.END)
        self.raw_text.delete(1.0, tk.END)
        self.captured_packets = []
        self.packet_count = 0
        self.update_statistics()
        self.status_var.set("Display cleared")
    
    def save_capture(self):
        if not self.captured_packets:
            messagebox.showinfo("Info", "No packets to save")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    for packet in self.captured_packets:
                        f.write(f"Packet #{packet['no']}\n")
                        f.write(f"Time: {packet['time']}\n")
                        f.write(f"Source: {packet['source']}\n")
                        f.write(f"Destination: {packet['destination']}\n")
                        f.write(f"Protocol: {packet['protocol']}\n")
                        f.write(f"Length: {packet['length']}\n")
                        f.write(f"Info: {packet['info']}\n")
                        f.write("Raw Data:\n")
                        f.write(packet['raw_hex'])
                        f.write("\n\n")
                    
                messagebox.showinfo("Success", f"Capture saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save capture: {str(e)}")
    
    def capture_packets(self):
        try:
            # Create a raw socket
            if os.name == 'nt':  # Windows
                # On Windows, the socket needs to be created differently
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                s.bind((socket.gethostbyname(socket.gethostname()), 0))
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:  # Linux/Mac
                s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            
            # Set a timeout to be able to check for stop capture
            s.settimeout(1)
            
            self.tcp_count = 0
            self.udp_count = 0
            self.icmp_count = 0
            self.other_count = 0
            
            while self.capture_active:
                try:
                    raw_data, addr = s.recvfrom(65535)
                    self.packet_count += 1
                    
                    # Process the packet
                    packet_info = self.process_packet(raw_data)
                    
                    # Apply filter if specified
                    if self.filter_text and self.filter_text.lower() not in str(packet_info).lower():
                        continue
                    
                    # Update statistics based on protocol
                    if packet_info['protocol'] == 'TCP':
                        self.tcp_count += 1
                    elif packet_info['protocol'] == 'UDP':
                        self.udp_count += 1
                    elif packet_info['protocol'] == 'ICMP':
                        self.icmp_count += 1
                    else:
                        self.other_count += 1
                    
                    # Store the packet
                    self.captured_packets.append(packet_info)
                    
                    # Update UI in the main thread
                    self.root.after(0, self.add_packet_to_ui, packet_info)
                    self.root.after(0, self.update_statistics)
                    
                except socket.timeout:
                    continue
                
            # Clean up
            if os.name == 'nt':
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            s.close()
            
        except Exception as e:
            self.root.after(0, lambda: self.status_var.set(f"Error: {str(e)}"))
            self.capture_active = False
            self.root.after(0, lambda: self.start_btn.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.stop_btn.config(state=tk.DISABLED))
    
    def process_packet(self, raw_data):
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        # For simplicity, we'll assume IPv4 packets
        # In a real application, you'd need to handle different ethernet frame types
        
        try:
            # Parse IP header
            ip_header = raw_data[0:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            
            version_ihl = iph[0]
            ihl = version_ihl & 0xF
            ip_header_length = ihl * 4
            
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8])
            d_addr = socket.inet_ntoa(iph[9])
            
            # Determine protocol
            if protocol == 6:  # TCP
                protocol_name = 'TCP'
                tcp_header = raw_data[ip_header_length:ip_header_length+20]
                tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                
                source_port = tcph[0]
                dest_port = tcph[1]
                sequence = tcph[2]
                acknowledgement = tcph[3]
                
                doff_reserved = tcph[4]
                tcph_length = doff_reserved >> 4
                
                info = f"TCP {source_port} → {dest_port} [Seq={sequence} Ack={acknowledgement}]"
                
            elif protocol == 17:  # UDP
                protocol_name = 'UDP'
                udp_header = raw_data[ip_header_length:ip_header_length+8]
                udph = struct.unpack('!HHHH', udp_header)
                
                source_port = udph[0]
                dest_port = udph[1]
                length = udph[2]
                
                info = f"UDP {source_port} → {dest_port} Len={length}"
                
            elif protocol == 1:  # ICMP
                protocol_name = 'ICMP'
                icmp_header = raw_data[ip_header_length:ip_header_length+8]
                icmph = struct.unpack('!BBHHH', icmp_header)
                
                icmp_type = icmph[0]
                code = icmph[1]
                checksum = icmph[2]
                
                icmp_types = {
                    0: "Echo Reply",
                    3: "Destination Unreachable",
                    8: "Echo Request",
                    11: "Time Exceeded"
                }
                
                type_str = icmp_types.get(icmp_type, f"Type {icmp_type}")
                info = f"ICMP {type_str} (code {code})"
                
            else:
                protocol_name = f'Other ({protocol})'
                info = f"Protocol: {protocol}"
            
            # Generate hex dump of the packet
            hex_dump = self.format_hex_dump(raw_data)
            
            return {
                'no': self.packet_count,
                'time': timestamp,
                'source': f"{s_addr}",
                'destination': f"{d_addr}",
                'protocol': protocol_name,
                'length': len(raw_data),
                'info': info,
                'raw_data': raw_data,
                'raw_hex': hex_dump
            }
            
        except Exception as e:
            return {
                'no': self.packet_count,
                'time': timestamp,
                'source': 'Error parsing',
                'destination': 'Error parsing',
                'protocol': 'Unknown',
                'length': len(raw_data),
                'info': f"Error parsing packet: {str(e)}",
                'raw_data': raw_data,
                'raw_hex': self.format_hex_dump(raw_data)
            }
    
    def format_hex_dump(self, data, per_row=16):
        hex_rows = []
        
        for i in range(0, len(data), per_row):
            chunk = data[i:i + per_row]
            hex_line = ' '.join(f'{byte:02x}' for byte in chunk)
            
            # Convert to ASCII (printable characters only)
            ascii_line = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in chunk)
            
            # Format row with offset, hex values, and ASCII representation
            row = f"{i:04x}:  {hex_line:<{3*per_row}}  {ascii_line}"
            hex_rows.append(row)
            
        return '\n'.join(hex_rows)
    
    def add_packet_to_ui(self, packet):
        self.packet_tree.insert('', 'end', values=(
            packet['no'],
            packet['time'],
            packet['source'],
            packet['destination'],
            packet['protocol'],
            packet['length'],
            packet['info']
        ))
    
    def update_statistics(self):
        stats = f"Packets: {self.packet_count} | TCP: {self.tcp_count} | UDP: {self.udp_count} | ICMP: {self.icmp_count} | Other: {self.other_count}"
        self.stats_var.set(stats)
    
    def on_packet_select(self, event):
        selection = self.packet_tree.selection()
        if selection:
            item = selection[0]
            item_id = int(self.packet_tree.item(item, 'values')[0]) - 1
            
            if 0 <= item_id < len(self.captured_packets):
                packet = self.captured_packets[item_id]
                self.display_packet_details(packet)
    
    def display_packet_details(self, packet):
        # Clear previous details
        self.details_text.delete(1.0, tk.END)
        self.raw_text.delete(1.0, tk.END)
        
        # Add packet details
        details = f"""Packet #{packet['no']}
Time: {packet['time']}
Length: {packet['length']} bytes

Source: {packet['source']}
Destination: {packet['destination']}
Protocol: {packet['protocol']}

Info: {packet['info']}
"""
        self.details_text.insert(tk.END, details)
        
        # Add raw hex dump
        self.raw_text.insert(tk.END, packet['raw_hex'])

if __name__ == "__main__":
    # Note: To run this program, you may need administrator/root privileges
    # since raw sockets require elevated permissions
    root = tk.Tk()
    app = NetworkSniffer(root)
    root.mainloop()