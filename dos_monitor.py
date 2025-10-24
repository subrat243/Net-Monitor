#!/usr/bin/env python3
import time
import os
import sys
import argparse
import logging
import subprocess
from collections import defaultdict
from threading import Thread, Lock
from scapy.all import sniff, IP, TCP, UDP, ICMP

# --- Configuration for Logging ---
def setup_logging(logfile):
    """Configures logging to both file and console."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        filename=logfile,
        filemode='a'
    )
    # Also log to the console
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
    logging.getLogger().addHandler(console_handler)

class DosDetector:
    """
    An improved DoS detector with configurable thresholds, logging, 
    whitelisting, and an optional mitigation function.
    """
    def __init__(self, config):
        # --- Configuration from args ---
        self.config = config
        self.TIME_WINDOW = config['time_window']
        self.THRESHOLDS = {
            'syn': config['syn_threshold'],
            'udp': config['udp_threshold'],
            'icmp': config['icmp_threshold']
        }
        self.whitelist = self.load_whitelist(config['whitelist_file'])

        # --- Internal State ---
        self.packet_counts = {
            'syn': defaultdict(int),
            'udp': defaultdict(int),
            'icmp': defaultdict(int)
        }
        self.lock = Lock()
        self.running = False

    def load_whitelist(self, file_path):
        """Loads a set of whitelisted IPs from a file."""
        if not file_path or not os.path.exists(file_path):
            return set()
        try:
            with open(file_path, 'r') as f:
                ips = {line.strip() for line in f if line.strip()}
                logging.info(f"Successfully loaded {len(ips)} IP(s) from whitelist.")
                return ips
        except Exception as e:
            logging.error(f"Could not load whitelist file: {e}")
            return set()

    def packet_handler(self, packet):
        """Categorizes and counts packets by source IP, ignoring whitelisted IPs."""
        if not self.running:
            return

        if IP in packet:
            src_ip = packet[IP].src

            # Ignore traffic from whitelisted IPs
            if src_ip in self.whitelist:
                return

            with self.lock:
                if TCP in packet and packet[TCP].flags == 0x02: # SYN Flag
                    self.packet_counts['syn'][src_ip] += 1
                elif UDP in packet:
                    self.packet_counts['udp'][src_ip] += 1
                elif ICMP in packet and packet[ICMP].type == 8: # Echo Request
                    self.packet_counts['icmp'][src_ip] += 1

    def monitor_and_detect(self):
        """Periodically analyzes packet counts to detect attacks."""
        logging.info("Starting detection thread...")
        while self.running:
            time.sleep(self.TIME_WINDOW)
            
            if not self.running: break
            
            with self.lock:
                counts_copy = {ptype: pcounts.copy() for ptype, pcounts in self.packet_counts.items()}
                for pcounts in self.packet_counts.values():
                    pcounts.clear()

            # Refactored analysis loop
            for attack_type, counts in counts_copy.items():
                threshold = self.THRESHOLDS[attack_type]
                for ip, count in counts.items():
                    if count > threshold:
                        rate = count / self.TIME_WINDOW
                        alert_msg = (f"Potential {attack_type.upper()} Flood detected from {ip}! "
                                     f"Rate: {rate:.2f} pps ({count} packets in {self.TIME_WINDOW}s)")
                        logging.warning(f"🚨 SECURITY ALERT: {alert_msg}")
                        
                        # --- Optional Mitigation Step ---
                        # Uncomment the line below to automatically block the IP
                        # self.block_ip(ip)

    def block_ip(self, ip_address):
        """Blocks an IP address using iptables. (Linux only)"""
        logging.info(f"Attempting to block IP: {ip_address}")
        try:
            # Use INSERT to add the rule at the top of the chain
            cmd = ['iptables', '-I', 'INPUT', '-s', ip_address, '-j', 'DROP']
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            logging.warning(f"✅ Successfully blocked {ip_address} with iptables.")
        except FileNotFoundError:
            logging.error("iptables command not found. Is this a Linux system?")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to block {ip_address}. Error: {e.stderr}")
        except Exception as e:
            logging.error(f"An unexpected error occurred while trying to block IP: {e}")

    def start(self):
        """Starts the packet sniffer and the monitor thread."""
        if self.running:
            logging.info("Detector is already running.")
            return

        logging.info("Starting DoS Monitor...")
        self.running = True
        
        self.monitor_thread = Thread(target=self.monitor_and_detect, daemon=True)
        self.monitor_thread.start()
        
        logging.info(f"Sniffing on interface: {'all' if not self.config['iface'] else self.config['iface']}")
        self.sniffer_thread = Thread(
            target=lambda: sniff(prn=self.packet_handler, store=False, 
                                 stop_filter=lambda p: not self.running, iface=self.config['iface']),
            daemon=True
        )
        self.sniffer_thread.start()

    def stop(self):
        """Stops the detector gracefully."""
        logging.info("Stopping DoS Monitor...")
        self.running = False
        time.sleep(1) # Give threads a moment to stop
        logging.info("Monitor stopped.")

def main():
    if os.geteuid() != 0:
        print("This tool requires root privileges. Please run with sudo.")
        sys.exit(1)
        
    parser = argparse.ArgumentParser(description="Advanced DoS Detector Tool")
    parser.add_argument('-i', '--iface', type=str, help="Interface to sniff on (e.g., eth0).")
    parser.add_argument('-l', '--logfile', type=str, default='dos_alerts.log', help="Log file for alerts.")
    parser.add_argument('-t', '--time-window', type=int, default=10, help="Time window in seconds for analysis.")
    parser.add_argument('--syn-threshold', type=int, default=100, help="SYN packets per window to trigger alert.")
    parser.add_argument('--udp-threshold', type=int, default=200, help="UDP packets per window to trigger alert.")
    parser.add_argument('--icmp-threshold', type=int, default=150, help="ICMP packets per window to trigger alert.")
    parser.add_argument('-w', '--whitelist-file', type=str, help="Path to a file containing whitelisted IPs (one per line).")

    args = parser.parse_args()
    config = vars(args)

    setup_logging(config['logfile'])
    detector = DosDetector(config)
    
    try:
        detector.start()
        while True:
            time.sleep(100) # Keep main thread alive
    except KeyboardInterrupt:
        detector.stop()
    except Exception as e:
        logging.critical(f"A critical error occurred: {e}")
        detector.stop()

if __name__ == "__main__":
    main()
