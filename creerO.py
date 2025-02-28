import socket
import nmap  # Bibliothèque pour le scan de ports
from concurrent.futures import ThreadPoolExecutor  # Pour le multithreading

def scan_port(target, port):
    """
    Scan un port spécifique sur une machine cible.
    :param target: Adresse IP ou nom de domaine de la cible.
    :param port: Port à scanner.
    :return: Tuple (port, True si ouvert, False sinon).
    """
    try:
        # Créer un socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Définir un timeout pour éviter les blocages
        # Essayer de se connecter au port
        result = sock.connect_ex((target, port))
        sock.close()
        return port, result == 0
    except Exception as e:
        print(f"Erreur lors du scan du port {port}: {e}")
        return port, False

def scan_ports(target, ports, max_threads=100):
    """
    Scan les ports ouverts sur une machine cible en utilisant le multithreading.
    :param target: Adresse IP ou nom de domaine de la cible.
    :param ports: Liste des ports à scanner.
    :param max_threads: Nombre maximal de threads pour le multithreading.
    :return: Liste des ports ouverts.
    """
    open_ports = []
    print(f"Scan des ports {ports} sur {target}...")

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(scan_port, target, port) for port in ports]
        for future in futures:
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)
                print(f"Port {port} ouvert.")

    return open_ports

def detect_vulnerable_services(target, open_ports):
    """
    Détecte les services vulnérables sur les ports ouverts.
    :param target: Adresse IP ou nom de domaine de la cible.
    :param open_ports: Liste des ports ouverts.
    :return: Dictionnaire des services vulnérables.
    """
    vulnerable_services = {}
    nm = nmap.PortScanner()  # Utiliser Nmap pour détecter les services

    for port in open_ports:
        try:
            # Scanner le port avec Nmap pour détecter le service
            nm.scan(target, str(port))
            service = nm[target]['tcp'][port]['name']
            version = nm[target]['tcp'][port]['version']

            # Vérifier si le service est vulnérable (exemple simplifié)
            if service == "ftp" and "2.3.4" in version:  # Exemple de vulnérabilité FTP
                vulnerable_services[port] = {"service": service, "version": version, "vulnerable": True}
            elif service == "http" and "Apache 2.2" in version:  # Exemple de vulnérabilité HTTP
                vulnerable_services[port] = {"service": service, "version": version, "vulnerable": True}
            else:
                vulnerable_services[port] = {"service": service, "version": version, "vulnerable": False}
        except Exception as e:
            print(f"Erreur lors de la détection du service sur le port {port}: {e}")
    return vulnerable_services

def generate_report(target, open_ports, vulnerable_services):
    """
    Génère un rapport du scan.
    :param target: Adresse IP ou nom de domaine de la cible.
    :param open_ports: Liste des ports ouverts.
    :param vulnerable_services: Dictionnaire des services vulnérables.
    """
    print(f"\nRapport de scan pour {target}:")
    print("=" * 40)
    print("Ports ouverts :")
    for port in open_ports:
        print(f" - Port {port} : {vulnerable_services[port]['service']} (Version: {vulnerable_services[port]['version']})")
    print("\nServices vulnérables :")
    for port, info in vulnerable_services.items():
        if info["vulnerable"]:
            print(f" - Port {port} : {info['service']} (Version: {info['version']}) est potentiellement vulnérable.")

def main():
    # Demander à l'utilisateur la cible
    target = input("Entrez l'adresse IP ou le nom de domaine de la cible : ")

    # Liste des ports à scanner (21, 23, 45, 22, 80, 43, 443, 2553)
    ports_to_scan = [21, 23, 45, 22, 80, 43, 443, 2553]

    # Scanner les ports
    print(f"\nDémarrage du scan des ports {ports_to_scan}...")
    open_ports = scan_ports(target, ports_to_scan)

    if open_ports:
        print(f"Ports ouverts trouvés : {open_ports}")
        # Détecter les services vulnérables
        vulnerable_services = detect_vulnerable_services(target, open_ports)
        # Générer le rapport
        generate_report(target, open_ports, vulnerable_services)
    else:
        print("Aucun port ouvert trouvé.")

if __name__ == "__main__":
    main()