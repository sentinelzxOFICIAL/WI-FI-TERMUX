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
            print(f"\033[1;31m\n[!] Erro:\n{result.stderr}\033[0m")
    except Exception as e:
        print(f"\033[1;31m\n[!] Erro ao executar o comando: {e}\033[0m")

def scan_wifi_nmcli():
    print("\033[1;34m\n[+] Escaneando redes Wi-Fi com nmcli...\033[0m\n")
    run_command("nmcli dev wifi list")

def scan_wifi_netsh():
    print("\033[1;34m\n[+] Escaneando redes Wi-Fi com netsh...\033[0m\n")
    run_command("netsh wlan show networks mode=Bssid")

def scan_wifi_iwlist():
    print("\033[1;34m\n[+] Escaneando redes Wi-Fi com iwlist...\033[0m\n")
    run_command("sudo iwlist scan")

def configure_wifi_iwconfig():
    print("\033[1;34m\n[+] Configurando Wi-Fi com iwconfig...\033[0m\n")
    run_command("iwconfig")

def arp_scan():
    print("\033[1;34m\n[+] Escaneando rede com arp-scan...\033[0m\n")
    run_command("sudo arp-scan -l")

def nmap_scan():
    print("\033[1;34m\n[+] Escaneando rede com nmap...\033[0m\n")
    run_command("nmap -sn 192.168.1.0/24")

def ping_test():
    print("\033[1;34m\n[+] Testando conectividade com ping...\033[0m\n")
    target = input("Digite o endereço IP ou URL para testar: ")
    run_command(f"ping -c 4 {target}" if platform.system() == "Linux" else f"ping {target}")

def traceroute_test():
    print("\033[1;34m\n[+] Rastreando rota com traceroute/tracert...\033[0m\n")
    target = input("Digite o endereço IP ou URL para rastrear: ")
    run_command(f"traceroute {target}" if platform.system() == "Linux" else f"tracert {target}")

def dig_dns():
    print("\033[1;34m\n[+] Consultando DNS com dig...\033[0m\n")
    domain = input("Digite o domínio para consultar: ")
    run_command(f"dig {domain}")

def host_dns():
    print("\033[1;34m\n[+] Consultando DNS com host...\033[0m\n")
    domain = input("Digite o domínio para consultar: ")
    run_command(f"host {domain}")

def scan_wifi_iw():
    print("\033[1;34m\n[+] Escaneando redes Wi-Fi com iw...\033[0m\n")
    run_command("iw dev wlan0 scan")

def airmon_ng():
    print("\033[1;34m\n[+] Gerenciando modos de monitoramento com airmon-ng...\033[0m\n")
    run_command("airmon-ng")

def airodump_ng():
    print("\033[1;34m\n[+] Capturando pacotes com airodump-ng...\033[0m\n")
    run_command("airodump-ng")

def aircrack_ng():
    print("\033[1;34m\n[+] Quebrando senhas com aircrack-ng...\033[0m\n")
    run_command("aircrack-ng")

def reaver_test():
    print("\033[1;34m\n[+] Testando vulnerabilidades WPS com reaver...\033[0m\n")
    run_command("reaver")

def mdk3_test():
    print("\033[1;34m\n[+] Testando redes com mdk3...\033[0m\n")
    run_command("mdk3")

def wash_test():
    print("\033[1;34m\n[+] Escaneando redes WPS com wash...\033[0m\n")
    run_command("wash")

def hcxdumptool_test():
    print("\033[1;34m\n[+] Capturando handshakes com hcxdumptool...\033[0m\n")
    run_command("hcxdumptool")

def hcxpcapngtool_test():
    print("\033[1;34m\n[+] Convertendo arquivos capturados com hcxpcapngtool...\033[0m\n")
    run_command("hcxpcapngtool")

def macchanger_test():
    print("\033[1;34m\n[+] Alterando endereço MAC com macchanger...\033[0m\n")
    run_command("macchanger")

def tcpdump_test():
    print("\033[1;34m\n[+] Capturando pacotes com tcpdump...\033[0m\n")
    run_command("tcpdump")

def wireshark_test():
    print("\033[1;34m\n[+] Capturando e analisando pacotes com wireshark...\033[0m\n")
    run_command("wireshark")

def tshark_test():
    print("\033[1;34m\n[+] Capturando e analisando pacotes com tshark...\033[0m\n")
    run_command("tshark")

def ettercap_test():
    print("\033[1;34m\n[+] Realizando ataques MITM com ettercap...\033[0m\n")
    run_command("ettercap")

def dmitry_test():
    print("\033[1;34m\n[+] Coletando informações com dmitry...\033[0m\n")
    run_command("dmitry")

def whatweb_test():
    print("\033[1;34m\n[+] Identificando tecnologias web com whatweb...\033[0m\n")
    run_command("whatweb")

def masscan_test():
    print("\033[1;34m\n[+] Escaneando portas com masscan...\033[0m\n")
    run_command("masscan")

def whois_test():
    print("\033[1;34m\n[+] Coletando informações WHOIS...\033[0m\n")
    domain = input("Digite o domínio para consultar: ")
    run_command(f"whois {domain}")

def netcat_test():
    print("\033[1;34m\n[+] Utilizando netcat...\033[0m\n")
    command = input("Digite o comando do netcat: ")
    run_command(f"nc {command}")

def curl_test():
    print("\033[1;34m\n[+] Utilizando curl...\033[0m\n")
    url = input("Digite a URL para realizar a requisição: ")
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
        {"name": "Scan de Redes Wi-Fi (nmcli)", "function": scan_wifi_nmcli},
        {"name": "Scan de Redes Wi-Fi (netsh)", "function": scan_wifi_netsh},
        {"name": "Scan de Redes Wi-Fi (iwlist)", "function": scan_wifi_iwlist},
        {"name": "Configurar Wi-Fi (iwconfig)", "function": configure_wifi_iwconfig},
        {"name": "Scan de Rede (arp-scan)", "function": arp_scan},
        {"name": "Scan de Rede (nmap)", "function": nmap_scan},
        {"name": "Teste de Conectividade (ping)", "function": ping_test},
        {"name": "Rastrear Rota (traceroute/tracert)", "function": traceroute_test},
        {"name": "Consulta DNS (dig)", "function": dig_dns},
        {"name": "Consulta DNS (host)", "function": host_dns},
        {"name": "Scan de Redes Wi-Fi (iw)", "function": scan_wifi_iw},
        {"name": "Modo de Monitoramento (airmon-ng)", "function": airmon_ng},
        {"name": "Captura de Pacotes (airodump-ng)", "function": airodump_ng},
{"name": "Quebra de Senhas (aircrack-ng)", "function": aircrack_ng},
        {"name": "Teste de Vulnerabilidade WPS (reaver)", "function": reaver_test},
        {"name": "Testes de Redes (mdk3)", "function": mdk3_test},
        {"name": "Escaneamento WPS (wash)", "function": wash_test},
        {"name": "Captura de Handshakes (hcxdumptool)", "function": hcxdumptool_test},
        {"name": "Conversão de Arquivos Capturados (hcxpcapngtool)", "function": hcxpcapngtool_test},
        {"name": "Alteração de Endereço MAC (macchanger)", "function": macchanger_test},
        {"name": "Captura de Pacotes (tcpdump)", "function": tcpdump_test},
        {"name": "Análise de Pacotes (wireshark)", "function": wireshark_test},
        {"name": "Análise de Pacotes (tshark)", "function": tshark_test},
        {"name": "Ataques MITM (ettercap)", "function": ettercap_test},
        {"name": "Coleta de Informações (dmitry)", "function": dmitry_test},
        {"name": "Identificação de Tecnologias Web (whatweb)", "function": whatweb_test},
        {"name": "Escaneamento de Portas (masscan)", "function": masscan_test},
        {"name": "Consulta WHOIS (whois)", "function": whois_test},
        {"name": "Utilização do Netcat (netcat)", "function": netcat_test},
        {"name": "Requisições Web (curl)", "function": curl_test},
        {"name": "DEVELOPED", "function": developed},
        {"name": "UPDATE", "function": update}
    ]

    print("\033[1;32mSelecione uma ferramenta para executar:\033[0m")
    for i, tool in enumerate(tools):
        print(f"\033[1;33m{i+1}. {tool['name']}\033[0m")

    tool_choice = input("\033[1;33mEscolha uma ferramenta para executar\033[0m").strip()
    
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
                print("\033[1;31m\n[!] Escolha inválida! Por favor, selecione um número válido.\033[0m")
        except ValueError:
            print("\033[1;31m\n[!] Escolha inválida! Por favor, selecione um número válido.\033[0m")