import subprocess
import os
import platform
import webbrowser

def banner():
    print("\033[1;32m")
    print("""
    ==========================================
    ||                                       ||
    ||           WIFI TERMUX                 ||
    ||                                       ||
    ||     dev:  @sentinelzxofc              ||
    ||    Github: sentinelzxOFICIAL          ||
    ||    version: 1.0                       ||
    ||                                       ||
    ==========================================
    """)
    print("\033[0m")

banner()
def run_command(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print(f"\033[1;31m\n[!] Error:\n{result.stderr}\033[0m")
    except Exception as e:
        print(f"\033[1;31m\n[!] Error executing command: {e}\033[0m")

def scan_wifi_nmcli():
    print("\033[1;34m\n[+] Scanning Wi-Fi networks with nmcli...\033[0m\n")
    run_command("nmcli dev wifi list")

def scan_wifi_netsh():
    print("\033[1;34m\n[+] Scanning Wi-Fi networks with netsh...\033[0m\n")
    run_command("netsh wlan show networks mode=Bssid")

def scan_wifi_iwlist():
    print("\033[1;34m\n[+] Scanning Wi-Fi networks with iwlist...\033[0m\n")
    run_command("sudo iwlist scan")

def configure_wifi_iwconfig():
    print("\033[1;34m\n[+] Configuring Wi-Fi with iwconfig...\033[0m\n")
    run_command("iwconfig")

def arp_scan():
    print("\033[1;34m\n[+] Scanning network with arp-scan...\033[0m\n")
    run_command("sudo arp-scan -l")

def nmap_scan():
    print("\033[1;34m\n[+] Scanning network with nmap...\033[0m\n")
    run_command("nmap -sn 192.168.1.0/24")

def ping_test():
    print("\033[1;34m\n[+] Testing connectivity with ping...\033[0m\n")
    target = input("Enter the IP address or URL to test: ")
    run_command(f"ping -c 4 {target}" if platform.system() == "Linux" else f"ping {target}")

def traceroute_test():
    print("\033[1;34m\n[+] Tracing route with traceroute/tracert...\033[0m\n")
    target = input("Enter the IP address or URL to trace: ")
    run_command(f"traceroute {target}" if platform.system() == "Linux" else f"tracert {target}")

def dig_dns():
    print("\033[1;34m\n[+] Querying DNS with dig...\033[0m\n")
    domain = input("Enter the domain to query: ")
    run_command(f"dig {domain}")

def host_dns():
    print("\033[1;34m\n[+] Querying DNS with host...\033[0m\n")
    domain = input("Enter the domain to query: ")
    run_command(f"host {domain}")

def scan_wifi_iw():
    print("\033[1;34m\n[+] Scanning Wi-Fi networks with iw...\033[0m\n")
    run_command("iw dev wlan0 scan")

def airmon_ng():
    print("\033[1;34m\n[+] Managing monitoring modes with airmon-ng...\033[0m\n")
    run_command("airmon-ng")

def airodump_ng():
    print("\033[1;34m\n[+] Capturing packets with airodump-ng...\033[0m\n")
    run_command("airodump-ng")

def aircrack_ng():
    print("\033[1;34m\n[+] Cracking passwords with aircrack-ng...\033[0m\n")
    run_command("aircrack-ng")

def reaver_test():
    print("\033[1;34m\n[+] Testing WPS vulnerabilities with reaver...\033[0m\n")
    run_command("reaver")

def mdk3_test():
    print("\033[1;34m\n[+] Testing networks with mdk3...\033[0m\n")
    run_command("mdk3")

def wash_test():
    print("\033[1;34m\n[+] Scanning WPS networks with wash...\033[0m\n")
    run_command("wash")

def hcxdumptool_test():
    print("\033[1;34m\n[+] Capturing handshakes with hcxdumptool...\033[0m\n")
    run_command("hcxdumptool")

def hcxpcapngtool_test():
    print("\033[1;34m\n[+] Converting captured files with hcxpcapngtool...\033[0m\n")
    run_command("hcxpcapngtool")

def macchanger_test():
    print("\033[1;34m\n[+] Changing MAC address with macchanger...\033[0m\n")
    run_command("macchanger")

def tcpdump_test():
    print("\033[1;34m\n[+] Capturing packets with tcpdump...\033[0m\n")
    run_command("tcpdump")

def wireshark_test():
    print("\033[1;34m\n[+] Capturing and analyzing packets with wireshark...\033[0m\n")
    run_command("wireshark")

def tshark_test():
    print("\033[1;34m\n[+] Capturing and analyzing packets with tshark...\033[0m\n")
    run_command("tshark")

def ettercap_test():
    print("\033[1;34m\n[+] Performing MITM attacks with ettercap...\033[0m\n")
    run_command("ettercap")

def dmitry_test():
    print("\033[1;34m\n[+] Gathering information with dmitry...\033[0m\n")
    run_command("dmitry")

def whatweb_test():
    print("\033[1;34m\n[+] Identifying web technologies with whatweb...\033[0m\n")
    run_command("whatweb")

def masscan_test():
    print("\033[1;34m\n[+] Scanning ports with masscan...\033[0m\n")
    run_command("masscan")

def whois_test():
    print("\033[1;34m\n[+] Gathering WHOIS information...\033[0m\n")
    domain = input("Enter the domain to query: ")
    run_command(f"whois {domain}")

def netcat_test():
    print("\033[1;34m\n[+] Using netcat...\033[0m\n")
    command = input("Enter the netcat command: ")
    run_command(f"nc {command}")

def curl_test():
    print("\033[1;34m\n[+] Using curl...\033[0m\n")
    url = input("Enter the URL to make the request: ")
    run_command(f"curl {url}")

def developed():
    print("\033[1;34m\n[+] Opening Developed URL...\033[0m\n")
    os.system('clear')
    os.system('bash r.sh')

def update():
    print("\033[1;34m\n[+] Starting Update Script...\033[0m\n")
    os.system('clear')
    os.system('python update.py')

if __name__ == "__main__":
    os.system('clear' if os.name == 'posix' else 'cls')
    banner()

    tools = [
        {"name": "Wi-Fi Network Scan (nmcli)", "function": scan_wifi_nmcli},
        {"name": "Wi-Fi Network Scan (netsh)", "function": scan_wifi_netsh},
        {"name": "Wi-Fi Network Scan (iwlist)", "function": scan_wifi_iwlist},
        {"name": "Configure Wi-Fi (iwconfig)", "function": configure_wifi_iwconfig},
        {"name": "Network Scan (arp-scan)", "function": arp_scan},
        {"name": "Network Scan (nmap)", "function": nmap_scan},
        {"name": "Connectivity Test (ping)", "function": ping_test},
        {"name": "Route Tracing (traceroute/tracert)", "function": traceroute_test},
        {"name": "DNS Query (dig)", "function": dig_dns},
        {"name": "DNS Query (host)", "function": host_dns},
        {"name": "Wi-Fi Network Scan (iw)", "function": scan_wifi_iw},
        {"name": "Monitoring Mode (airmon-ng)", "function": airmon_ng},
        {"name": "Packet Capture (airodump-ng)", "function": airodump_ng},
        {"name": "Password Cracking (aircrack-ng)", "function": aircrack_ng},
        {"name": "WPS Vulnerability Testing (reaver)", "function": reaver_test},
        {"name": "Network Testing (mdk3)", "function": mdk3_test},
        {"name": "WPS Scanning (wash)", "function": wash_test},
        {"name": "Handshake Capture (hcxdumptool)", "function": hcxdumptool_test},
        {"name": "Captured File Conversion (hcxpcapngtool)", "function": hcxpcapngtool_test},
        {"name": "MAC Address Change (macchanger)", "function": macchanger_test},
        {"name": "Packet Capture (tcpdump)", "function": tcpdump_test},
        {"name": "Packet Analysis (wireshark)", "function": wireshark_test},
        {"name": "Packet Analysis (tshark)", "function": tshark_test},
        {"name": "MITM Attacks (ettercap)", "function": ettercap_test},
        {"name": "Information Gathering (dmitry)", "function": dmitry_test},
        {"name": "Web Technology Identification (whatweb)", "function": whatweb_test},
        {"name": "Port Scanning (masscan)", "function": masscan_test},
        {"name": "WHOIS Query (whois)", "function": whois_test},
        {"name": "Netcat Usage (netcat)", "function": netcat_test},
        {"name": "Web Requests (curl)", "function": curl_test},
        {"name": "DEVELOPED", "function": developed},
        {"name": "UPDATE", "function": update}
    ]

    print("\033[1;32mSelect a tool to run:\033[0m")
    for i, tool in enumerate(tools):
        print(f"\033[1;33m{i+1}. {tool['name']}\033[0m")

    tool_choice = input("\033[1;33mChoose a tool to run: \033[0m").strip()
    
    if tool_choice.lower() in ['d', 'developed']:
        developed()
    elif tool_choice.lower() in ['p', 'update']:
        update()
    else:
        try:
            tool_choice = int(tool_choice) - 1
            if 0 <= tool_choice < len(tools):
                tools[tool_choice]["function"]()
            else:
                print("\033[1;31m\n[!] Invalid choice! Please select a valid number.\033[0m")
        except ValueError:
            print("\033[1;31m\n[!] Invalid choice! Please select a valid number.\033[0m")
