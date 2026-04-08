"""
Dangerous Open Ports Check
Checks if database/service ports are accidentally exposed to the internet.
Passive TCP connect check — no exploitation, no data sent.
"""
import socket
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

TIMEOUT = 3

DANGEROUS_PORTS = [
    (3306, "MySQL baza podataka", "CRITICAL",
     "MySQL port je otvoren! Napadač može pokušati direktnu konekciju na bazu podataka.",
     "MySQL port is open! An attacker can attempt a direct database connection.",
     "Zatvorite port 3306 za javne IP adrese. MySQL treba biti dostupan samo lokalno ili kroz VPN.",
     "Close port 3306 to public IPs. MySQL should only be accessible locally or via VPN."),

    (5432, "PostgreSQL baza podataka", "CRITICAL",
     "PostgreSQL port je otvoren! Direktan pristup bazi sa interneta je izuzetno opasan.",
     "PostgreSQL port is open! Direct database access from the internet is extremely dangerous.",
     "Zatvorite port 5432 firewallom. Koristite SSH tunel ili VPN za administratorski pristup.",
     "Close port 5432 with a firewall. Use SSH tunnel or VPN for admin access."),

    (27017, "MongoDB (bez autentifikacije?)", "CRITICAL",
     "MongoDB port je otvoren! MongoDB istorijski ima poznate probleme sa defaultnom konfiguracijom bez lozinke.",
     "MongoDB port is open! MongoDB historically has known issues with default no-password configuration.",
     "Zatvorite port 27017. Omogućite MongoDB autentifikaciju i bind samo na localhost.",
     "Close port 27017. Enable MongoDB authentication and bind to localhost only."),

    (6379, "Redis (cache/session store)", "CRITICAL",
     "Redis port je otvoren! Redis često nema autentifikaciju po defaultu i napadač može čitati/brisati sve session podatke.",
     "Redis port is open! Redis often has no authentication by default and an attacker can read/delete all session data.",
     "Zatvorite port 6379. Dodajte Redis lozinku (requirepass) i bind na 127.0.0.1.",
     "Close port 6379. Add Redis password (requirepass) and bind to 127.0.0.1."),

    (9200, "Elasticsearch", "CRITICAL",
     "Elasticsearch port je otvoren! Stare verzije Elasticsearch nemaju autentifikaciju — svi podaci su javni.",
     "Elasticsearch port is open! Old Elasticsearch versions have no authentication — all data is public.",
     "Zatvorite port 9200. Koristite X-Pack security za autentifikaciju ili stavite iza reverse proxy-ja.",
     "Close port 9200. Use X-Pack security for authentication or place behind a reverse proxy."),

    (21, "FTP server", "HIGH",
     "FTP port je otvoren. FTP prenosi lozinke i podatke nešifrovano — lakoća za presretanje.",
     "FTP port is open. FTP transmits passwords and data unencrypted — easy to intercept.",
     "Ugasite FTP i koristite SFTP (port 22) umesto toga. FTP je zastarela tehnologija.",
     "Shut down FTP and use SFTP (port 22) instead. FTP is an outdated technology."),

    (23, "Telnet", "CRITICAL",
     "Telnet port je otvoren! Telnet prenosi sve uključujući lozinke potpuno nešifrovano.",
     "Telnet port is open! Telnet transmits everything including passwords completely unencrypted.",
     "Odmah ugasite Telnet. Koristite SSH umesto toga.",
     "Immediately shut down Telnet. Use SSH instead."),

    (11211, "Memcached", "HIGH",
     "Memcached port je otvoren. Može se koristiti za DDoS amplifikaciju napad i pristup cache-ovanim podacima.",
     "Memcached port is open. Can be used for DDoS amplification attacks and access to cached data.",
     "Zatvorite port 11211 firewallom. Bind Memcached na 127.0.0.1.",
     "Close port 11211 with a firewall. Bind Memcached to 127.0.0.1."),

    (8080, "Alternativni HTTP port", "MEDIUM",
     "Port 8080 je otvoren (alternativni web server). Može biti testni server sa slabijom konfiguracijom.",
     "Port 8080 is open (alternative web server). May be a test server with weaker configuration.",
     "Ako je testni server — ugasite ga u produkciji. Ako je potreban, dodajte HTTPS i autentifikaciju.",
     "If it's a test server — shut it down in production. If needed, add HTTPS and authentication."),

    (8443, "Alternativni HTTPS port", "LOW",
     "Port 8443 je otvoren. Proverite da li je ovo namerno.",
     "Port 8443 is open. Verify if this is intentional.",
     "Proverite šta radi servis na ovom portu i da li je potreban.",
     "Check what service is running on this port and if it is needed."),
]


def _check_port(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def run(domain: str) -> List[Dict[str, Any]]:
    results = []
    open_ports = []

    # Run port checks concurrently for speed
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_port = {
            executor.submit(_check_port, domain, port): (port, name, severity, desc_sr, desc_en, rec_sr, rec_en)
            for port, name, severity, desc_sr, desc_en, rec_sr, rec_en in DANGEROUS_PORTS
        }
        for future in as_completed(future_to_port):
            port_data = future_to_port[future]
            port, name, severity, desc_sr, desc_en, rec_sr, rec_en = port_data
            try:
                is_open = future.result()
                if is_open:
                    open_ports.append((port, name, severity, desc_sr, desc_en, rec_sr, rec_en))
            except Exception:
                pass

    if open_ports:
        for port, name, severity, desc_sr, desc_en, rec_sr, rec_en in open_ports:
            results.append({
                "id": f"port_{port}_open",
                "category": "Open Ports",
                "severity": severity,
                "passed": False,
                "title": f"Port {port} otvoren: {name}",
                "title_en": f"Port {port} open: {name}",
                "description": desc_sr,
                "description_en": desc_en,
                "recommendation": rec_sr,
                "recommendation_en": rec_en,
            })
    else:
        results.append({
            "id": "ports_all_closed",
            "category": "Open Ports",
            "severity": "INFO",
            "passed": True,
            "title": f"Provereno {len(DANGEROUS_PORTS)} opasnih portova — svi zatvoreni ✓",
            "title_en": f"Checked {len(DANGEROUS_PORTS)} dangerous ports — all closed ✓",
            "description": "MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch, FTP, Telnet, Memcached — nijedan nije javno dostupan.",
            "description_en": "MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch, FTP, Telnet, Memcached — none are publicly accessible.",
            "recommendation": "",
            "recommendation_en": "",
        })

    return results
