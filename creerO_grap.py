import socket
import nmap
import tkinter as tk
from tkinter import ttk, scrolledtext
from concurrent.futures import ThreadPoolExecutor

# Base des services connus par port
PORT_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP Proxy"
}


def scan_port(target, port):
    """Scanne un port spécifique sur une machine cible."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        sock.close()
        return port, result == 0
    except Exception as e:
        return port, False


def scan_ports(target, ports, progress_bar, result_text):
    """Scanne plusieurs ports et met à jour l'interface graphique."""
    open_ports = []
    progress_bar["value"] = 0
    progress_bar["maximum"] = len(ports)
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(scan_port, target, port) for port in ports]
        for future in futures:
            port, is_open = future.result()
            progress_bar["value"] += 1
            root.update_idletasks()

            if is_open:
                open_ports.append(port)
                service = PORT_SERVICES.get(port, "Inconnu")
                result_text.insert(tk.END, f"✅ Port {port} ouvert ({service})\n")
                result_text.yview(tk.END)

    return open_ports


def detect_services(target, open_ports, result_text):
    """Détecte les services actifs sur les ports ouverts."""
    services = {}
    nm = nmap.PortScanner()

    for port in open_ports:
        try:
            nm.scan(target, str(port))
            if target in nm.all_hosts():
                if 'tcp' in nm[target] and port in nm[target]['tcp']:
                    service = nm[target]['tcp'][port].get('name', PORT_SERVICES.get(port, "Inconnu"))
                    version = nm[target]['tcp'][port].get('version', "Inconnue")
                    services[port] = {"service": service, "version": version}
                else:
                    services[port] = {"service": PORT_SERVICES.get(port, "Inconnu"), "version": "Inconnue"}
        except:
            services[port] = {"service": PORT_SERVICES.get(port, "Inconnu"), "version": "Inconnue"}

    result_text.insert(tk.END, "\n📋 Services détectés :\n")
    for port, info in services.items():
        result_text.insert(tk.END, f"  - Port {port}: {info['service']} (Version: {info['version']})\n")
        result_text.yview(tk.END)

    return services


def check_vulnerabilities(services, result_text):
    """Vérifie si certains services sont vulnérables."""
    result_text.insert(tk.END, "\n⚠️ Recherche de vulnérabilités...\n")
    for port, info in services.items():
        if info["service"] == "FTP" and "2.3.4" in info["version"]:
            result_text.insert(tk.END, f"🚨 Vulnérabilité détectée sur le port {port} (FTP 2.3.4)\n")
        elif info["service"] == "HTTP" and "Apache 2.2" in info["version"]:
            result_text.insert(tk.END, f"🚨 Vulnérabilité détectée sur le port {port} (Apache 2.2)\n")
    
    result_text.yview(tk.END)


def run_scan():
    """Exécute le scan avec l'interface graphique."""
    target = ip_entry.get()
    result_text.delete("1.0", tk.END)

    if not target:
        result_text.insert(tk.END, "❌ Veuillez entrer une adresse IP ou un domaine valide.\n")
        return

    result_text.insert(tk.END, f"🚀 Scan en cours sur {target}...\n")
    
    ports_to_scan = list(PORT_SERVICES.keys())

    open_ports = scan_ports(target, ports_to_scan, progress_bar, result_text)

    if open_ports:
        result_text.insert(tk.END, f"\n🎯 Ports ouverts trouvés : {open_ports}\n")
        services = detect_services(target, open_ports, result_text)
        check_vulnerabilities(services, result_text)
    else:
        result_text.insert(tk.END, "🚫 Aucun port ouvert trouvé.\n")


# Interface graphique Tkinter
root = tk.Tk()
root.title("Scanner de Ports 🔍")
root.geometry("600x500")
root.resizable(False, False)

# Zone de saisie de l'IP
tk.Label(root, text="Adresse IP/Domaine:", font=("Arial", 12)).pack(pady=5)
ip_entry = tk.Entry(root, width=40, font=("Arial", 12))
ip_entry.pack(pady=5)

# Bouton pour lancer le scan
scan_button = tk.Button(root, text="Lancer le Scan", font=("Arial", 12), bg="#007BFF", fg="white", command=run_scan)
scan_button.pack(pady=10)

# Barre de progression
progress_bar = ttk.Progressbar(root, orient="horizontal", length=500, mode="determinate")
progress_bar.pack(pady=5)

# Zone d'affichage des résultats
result_text = scrolledtext.ScrolledText(root, width=70, height=20, font=("Arial", 10))
result_text.pack(pady=5)

# Lancer l'interface
root.mainloop()
