from scapy.all import *
import os

# Mots-clés pour détection de données sensibles
sensitive_keys = ["user", "username", "email", "pass", "password", "login", "pwd", "token", "auth"]

def extract_http_fields(pkt):
    if pkt.haslayer(Raw) and pkt.haslayer(TCP):
        payload = pkt[Raw].load.decode(errors="ignore")

        # Requête HTTP simple
        if payload.startswith(("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH")):
            print("\n--- Requête HTTP trouvée ---\n")
            lines = payload.split('\r\n')
            request_line = lines[0]
            try:
                method, uri, version = request_line.split()
            except:
                print("[!] Ligne de requête invalide")
                return
            
            print(f"→ Méthode : {method}")
            print(f"→ URI : {uri}")
            print(f"→ Version : {version}")

            # Extraction des headers
            headers = {}
            for line in lines[1:]:
                if ": " in line:
                    key, value = line.split(": ", 1)
                    headers[key] = value
            
            # Affichage complet des headers
            print("\n→ En-têtes HTTP :")
            for key, value in headers.items():
                print(f"   {key}: {value}")

            # URL complète
            host = headers.get("Host", "")
            full_url = f"http://{host}{uri}"
            print(f"\n→ URL complète : {full_url}")

            # Paramètres GET
            if method == "GET" and "?" in uri:
                print("\n→ Paramètres GET :")
                params = uri.split("?", 1)[1]
                for param in params.split("&"):
                    if "=" in param:
                        key, value = param.split("=", 1)
                        if any(s in key.lower() for s in sensitive_keys):
                            print(f"   {key} = {value}")
                        else:
                            print(f"   {key} = {value}")

            # Paramètres POST
            if method == "POST":
                try:
                    body = payload.split("\r\n\r\n", 1)[1]
                    print("\n→ Corps POST brut :")
                    print(body)

                    print("\n→ Paramètres POST :")
                    for param in body.split("&"):
                        if "=" in param:
                            key, value = param.split("=", 1)
                            if any(s in key.lower() for s in sensitive_keys):
                                print(f"   {key} = {value}")
                            else:
                                print(f"   {key} = {value}")
                except IndexError:
                    print("\n[!] Pas de corps POST trouvé.")

            # Champs spécifiques
            if "User-Agent" in headers:
                print(f"\n→ User-Agent : {headers['User-Agent']}")
            if "Referer" in headers:
                print(f"→ Referer : {headers['Referer']}")
            if "Cookie" in headers:
                print(f"→ Cookies : {headers['Cookie']}")
            if "Authorization" in headers:
                print(f"→ Authorization : {headers['Authorization']}")
            if "Content-Type" in headers:
                print(f"→ Content-Type : {headers['Content-Type']}")
            if "Content-Length" in headers:
                print(f"→ Content-Length : {headers['Content-Length']}")

            print("\n----------------------------\n")

# Lecture du fichier pcap
base_dir = os.path.dirname(os.path.abspath(__file__))  # chemin de dossier courant
pcap_file = os.path.normpath(os.path.join(base_dir, ".", "http-vs-https-analyser_http-password.pcap")) 
packets = rdpcap(pcap_file)
for pkt in packets:
    extract_http_fields(pkt)
