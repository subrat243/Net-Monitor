# DoS Attack Monitor

An Python-based Intrusion Detection System (IDS) for detecting network flood attacks like **TCP SYN floods**, **UDP floods**, and **ICMP floods** in real-time. This tool monitors network traffic, analyzes packet rates against configurable thresholds, and provides detailed alerts with optional, automated mitigation.

-----

## Key Features

  - **Real-Time Detection**: Monitors network traffic live to identify potential DoS attacks as they happen.
  - **Highly Configurable**: Use command-line arguments to set packet thresholds, monitoring interfaces, and log file paths.
  - **Detailed Logging**: All alerts and system messages are logged to a file with timestamps for persistent record-keeping and later analysis.
  - **IP Whitelisting**: Prevents false positives by ignoring traffic from a user-defined list of trusted IP addresses.
  - **Automated Mitigation**: Includes an optional feature to automatically block an attacker's IP address using `iptables` on Linux systems.

-----

## Requirements

  - **Python 3.x**
  - **`scapy` library**
  - **Root/Administrator privileges** to run the packet sniffer.
  - **`iptables`** (for the optional IP blocking feature on Linux).

-----

## Installation

1.  **Clone the repository or download the `dos_monitor_v2.py` script.**

2.  **Install the `scapy` library using pip:**

    ```bash
    pip install scapy
    ```

-----

## Usage

The script must be run with `sudo` because it requires root privileges to capture network packets.

```bash
sudo python3 dos_monitor_v2.py [OPTIONS]
```

### Command-Line Arguments

You can view all available options by running the script with the `-h` or `--help` flag.

```
usage: dos_monitor_v2.py [-h] [-i IFACE] [-l LOGFILE] [-t TIME_WINDOW]
                         [--syn-threshold SYN_THRESHOLD]
                         [--udp-threshold UDP_THRESHOLD]
                         [--icmp-threshold ICMP_THRESHOLD]
                         [-w WHITELIST_FILE]

Advanced DoS Detector Tool

options:
  -h, --help            show this help message and exit
  -i IFACE, --iface IFACE
                        Interface to sniff on (e.g., eth0).
  -l LOGFILE, --logfile LOGFILE
                        Log file for alerts.
  -t TIME_WINDOW, --time-window TIME_WINDOW
                        Time window in seconds for analysis.
  --syn-threshold SYN_THRESHOLD
                        SYN packets per window to trigger alert.
  --udp-threshold UDP_THRESHOLD
                        UDP packets per window to trigger alert.
  --icmp-threshold ICMP_THRESHOLD
                        ICMP packets per window to trigger alert.
  -w WHITELIST_FILE, --whitelist-file WHITELIST_FILE
                        Path to a file containing whitelisted IPs (one per line).
```

### Examples

  * **Run with default settings:**

    ```bash
    sudo python3 dos_monitor_v2.py
    ```

  * **Monitor a specific network interface (`eth0`) and use a whitelist:**

    ```bash
    sudo python3 dos_monitor_v2.py --iface eth0 --whitelist-file whitelist.txt
    ```

  * **Set more aggressive thresholds and a custom log file:**

    ```bash
    sudo python3 dos_monitor_v2.py --syn-threshold 50 --udp-threshold 100 --logfile /var/log/dos_alerts.log
    ```

-----

## Configuration

### Whitelist File

To prevent the monitor from flagging trusted, high-traffic servers, create a simple text file (e.g., `whitelist.txt`) and list each IP address on a new line.

**Example `whitelist.txt`:**

```
192.168.1.1
10.0.0.5
8.8.8.8
```

### Automated IP Blocking (Mitigation)

This tool includes a function to automatically block attacking IPs using `iptables`. This is a powerful feature that can prevent attacks but carries the risk of blocking legitimate traffic if thresholds are misconfigured.

**This feature is disabled by default.**

To enable it:

1.  Open the `dos_monitor_v2.py` script.
2.  Navigate to the `monitor_and_detect` method.
3.  Find and uncomment the following line:
    ```python
    # self.block_ip(ip)
    ```
    to
    ```python
    self.block_ip(ip)
    ```

-----

## License

This project is licensed under the **MIT License**. See the `LICENSE` file for details.
