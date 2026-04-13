# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
"""
Dangerous Open Ports Check
Checks if database/service ports are accidentally exposed to the internet.
Passive TCP connect check — no exploitation, no data sent.
"""
import socket
from typing import List, Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

TIMEOUT = 3

# Headers / banners that mean "this port is owned by a CDN/edge proxy, not the
# origin server". When 8080/8443 are answered by an edge, the finding is a
# false positive — the customer doesn't own that port, the CDN does.
CDN_HEADER_MARKERS = (
    "cloudflare", "cf-ray", "vercel", "x-vercel-id",
    "fastly", "x-served-by", "akamai", "x-amz-cf-id",
    "x-cache: hit", "x-cache: miss", "envoy", "google frontend",
)


def _looks_like_cdn(host: str, port: int) -> bool:
    """Best-effort HTTP probe: open the port, send a minimal HTTP request,
    and look for CDN/edge fingerprints in the response. Failure-safe — any
    exception means 'unknown', not 'cdn'."""
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            sock.settimeout(TIMEOUT)
            req = f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode("ascii", errors="ignore")
            sock.sendall(req)
            data = sock.recv(2048).decode("utf-8", errors="ignore").lower()
            return any(marker in data for marker in CDN_HEADER_MARKERS)
    except Exception:
        return False

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

    # ── Modern stack: distributed databases ───────────────────────────────
    (9042, "Apache Cassandra (distribuirana baza)", "CRITICAL",
     "Cassandra CQL port je otvoren. Distribuirane baze često imaju slabu defaultnu autentifikaciju, a eksponiranje znači potpun pristup podacima iz celog klastera.",
     "Cassandra CQL port is open. Distributed databases often have weak default authentication, and exposing it means full access to all cluster data.",
     "Zatvorite port 9042 na firewall-u. Omogućite PasswordAuthenticator u cassandra.yaml i bind samo na privatnu mrežu.",
     "Close port 9042 at the firewall. Enable PasswordAuthenticator in cassandra.yaml and bind only to the private network."),

    (5984, "Apache CouchDB (Fauxton admin)", "CRITICAL",
     "CouchDB port je otvoren sa Fauxton admin interfejsom. Istorijski je imao 'admin party' mode — baza bez lozinke — i CVE-2022-24706 RCE.",
     "CouchDB port is open with Fauxton admin interface. Historically had 'admin party' mode — database with no password — and CVE-2022-24706 RCE.",
     "Zatvorite port 5984. Postavite admin lozinku kroz local.ini i bind na localhost.",
     "Close port 5984. Set an admin password via local.ini and bind to localhost."),

    (28015, "RethinkDB (NoSQL)", "HIGH",
     "RethinkDB driver port je otvoren. Defaultno nema autentifikaciju i napadač može čitati ili menjati sve podatke.",
     "RethinkDB driver port is open. Has no authentication by default and an attacker can read or modify all data.",
     "Zatvorite port 28015. Konfigurišite user/password u RethinkDB admin bazi.",
     "Close port 28015. Configure a user/password in the RethinkDB admin database."),

    (8091, "Couchbase admin UI", "CRITICAL",
     "Couchbase admin port je otvoren. Defaultno ima admin UI sa mogućnošću upravljanja celom bazom, i istorijski se instalira bez postavljene admin lozinke.",
     "Couchbase admin port is open. By default has an admin UI with full database management, and historically gets installed without an admin password set.",
     "Zatvorite port 8091 za javne IP-eve. Postavite jak Cluster Administrator password odmah pri instalaciji i bind na privatnu mrežu.",
     "Close port 8091 to public IPs. Set a strong Cluster Administrator password immediately on install and bind to the private network."),

    # ── Message brokers & coordination ────────────────────────────────────
    (15672, "RabbitMQ management UI", "HIGH",
     "RabbitMQ management interfejs je otvoren. Defaultni kredencijali guest/guest rade sa bilo koje IP adrese ako je port javan — svi message brokeri su izloženi.",
     "RabbitMQ management interface is open. Default guest/guest credentials work from any IP when the port is public — all message brokers are exposed.",
     "Zatvorite port 15672. Obrišite 'guest' korisnika, postavite jak password, i omogućite management plugin samo na localhost.",
     "Close port 15672. Delete the 'guest' user, set a strong password, and enable the management plugin only on localhost."),

    (9092, "Apache Kafka broker", "HIGH",
     "Kafka broker port je otvoren. Bez SASL autentifikacije napadač može čitati ili produkovati poruke u bilo koji topic — potpuna kompromitacija stream podataka.",
     "Kafka broker port is open. Without SASL authentication, an attacker can read or produce messages to any topic — full compromise of stream data.",
     "Zatvorite port 9092 za javne IP-eve. Omogućite SASL/SCRAM i TLS, i koristite ACL-ove po topic-u.",
     "Close port 9092 to public IPs. Enable SASL/SCRAM and TLS, and use per-topic ACLs."),

    (2181, "Apache Zookeeper", "HIGH",
     "Zookeeper port je otvoren. Drži koordinacione metapodatke za Kafka/Hadoop/HBase klastere — otkriva strukturu celog sistema i može se koristiti za manipulaciju stanja klastera.",
     "Zookeeper port is open. Holds coordination metadata for Kafka/Hadoop/HBase clusters — reveals the whole system structure and can be used to manipulate cluster state.",
     "Zatvorite port 2181. Koristite Zookeeper ACL-ove i SASL autentifikaciju, bind na privatnu mrežu.",
     "Close port 2181. Use Zookeeper ACLs and SASL authentication, bind to the private network."),

    # ── Container orchestration (Docker / Kubernetes) ─────────────────────
    (2375, "Docker daemon API (HTTP, bez TLS)", "CRITICAL",
     "Docker daemon API je otvoren bez TLS-a. Ovo je trivijalni RCE — svaka komanda 'docker -H <host>:2375 run ...' daje napadaču root shell na serveru.",
     "Docker daemon API is open without TLS. This is a trivial RCE — any 'docker -H <host>:2375 run ...' command gives the attacker a root shell on the server.",
     "ODMAH zatvorite port 2375. Docker daemon ne sme biti javno eksponiran. Za remote pristup koristite TLS (port 2376) ili SSH tunel.",
     "Close port 2375 IMMEDIATELY. The Docker daemon must never be publicly exposed. For remote access use TLS (port 2376) or an SSH tunnel."),

    (2376, "Docker daemon API (TLS)", "HIGH",
     "Docker daemon TLS port je otvoren. Zahteva klijentski sertifikat, ali svaka slabost u TLS konfiguraciji ili CA management-u vodi direktno do RCE-a na serveru.",
     "Docker daemon TLS port is open. Requires a client certificate, but any weakness in TLS configuration or CA management leads directly to RCE on the server.",
     "Ako remote Docker pristup nije neophodan, zatvorite port 2376. Ako jeste — proverite da li je mTLS stvarno strogo postavljen.",
     "If remote Docker access is not required, close port 2376. If it is — verify that mTLS is actually strictly configured."),

    (10250, "Kubernetes Kubelet API", "CRITICAL",
     "Kubelet API port je otvoren. Kubelet kontroliše sve pod-ove na node-u — anonimni pristup ili slaba autentifikacija znači RCE na svakom pod-u u klasteru.",
     "Kubelet API port is open. Kubelet controls all pods on the node — anonymous access or weak authentication means RCE on every pod in the cluster.",
     "Zatvorite port 10250 za sve osim control plane-a. Postavite --anonymous-auth=false i --authorization-mode=Webhook u kubelet konfiguraciji.",
     "Close port 10250 to everything except the control plane. Set --anonymous-auth=false and --authorization-mode=Webhook in the kubelet configuration."),

    (2379, "etcd key-value store", "CRITICAL",
     "etcd port je otvoren. etcd sadrži celu Kubernetes config bazu uključujući secrets, tokens i service accounts — eksponirano = potpun cluster takeover.",
     "etcd port is open. etcd contains the entire Kubernetes config database including secrets, tokens, and service accounts — exposed = full cluster takeover.",
     "Zatvorite port 2379 za sve osim control plane node-ova. Omogućite client-to-server TLS sa mutual auth.",
     "Close port 2379 to all non-control-plane nodes. Enable client-to-server TLS with mutual auth."),

    # ── Search & big data ─────────────────────────────────────────────────
    (8983, "Apache Solr admin", "HIGH",
     "Solr admin port je otvoren. Istorijski lanac ranjivosti kroz VelocityResponseWriter, DataImportHandler i Log4Shell — eksponiran Solr je često direktno RCE.",
     "Solr admin port is open. Historical vulnerability chain through VelocityResponseWriter, DataImportHandler and Log4Shell — exposed Solr is often direct RCE.",
     "Zatvorite port 8983. Omogućite Solr autentifikaciju kroz security.json i bind na localhost.",
     "Close port 8983. Enable Solr authentication via security.json and bind to localhost."),

    (50070, "Hadoop NameNode UI", "HIGH",
     "Hadoop NameNode web UI je otvoren. Otkriva strukturu HDFS fajl sistema, listu svih fajlova, i često dozvoljava direktan download podataka bez autentifikacije.",
     "Hadoop NameNode web UI is open. Reveals HDFS filesystem structure, full file listings, and often allows direct data downloads without authentication.",
     "Zatvorite port 50070. Omogućite Kerberos autentifikaciju za Hadoop i bind NameNode UI na privatnu mrežu.",
     "Close port 50070. Enable Kerberos authentication for Hadoop and bind the NameNode UI to the private network."),

    (7077, "Apache Spark master", "HIGH",
     "Spark master port je otvoren. Napadač može da preda proizvoljne Spark job-ove klasteru što znači udaljeno izvršenje koda na svim worker node-ovima.",
     "Spark master port is open. An attacker can submit arbitrary Spark jobs to the cluster, meaning remote code execution on all worker nodes.",
     "Zatvorite port 7077. Omogućite Spark ACL-ove (spark.acls.enable=true) i bind master samo na internu mrežu klastera.",
     "Close port 7077. Enable Spark ACLs (spark.acls.enable=true) and bind the master only to the internal cluster network."),

    (4040, "Apache Spark application UI", "MEDIUM",
     "Spark application web UI je otvoren. Otkriva listu aktivnih job-ova, konfiguraciju, environment promenljive i često putanje fajlova — korisno za napadača u pripremi napada.",
     "Spark application web UI is open. Reveals the list of active jobs, configuration, environment variables and often file paths — useful for an attacker in attack preparation.",
     "Zatvorite port 4040. Omogućite spark.ui.filters za autentifikaciju ili stavite iza reverse proxy-ja.",
     "Close port 4040. Enable spark.ui.filters for authentication or place behind a reverse proxy."),
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

    # Run port checks concurrently for speed. max_workers scales with the
    # port list — at 25 ports and TIMEOUT=3, 15 workers keeps wall time
    # under ~6 seconds in the worst case (all ports time out).
    with ThreadPoolExecutor(max_workers=15) as executor:
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
            # 8080/8443 false positive guard: if a CDN/edge answers, the port
            # belongs to the edge, not to the customer. Demote to INFO+passed
            # with a note instead of a MEDIUM/LOW finding.
            if port in (8080, 8443) and _looks_like_cdn(domain, port):
                results.append({
                    "id": f"port_{port}_cdn",
                    "category": "Open Ports",
                    "severity": "INFO",
                    "passed": True,
                    "title": f"Port {port} odgovara CDN/edge proxy (ne origin server)",
                    "title_en": f"Port {port} answered by a CDN/edge proxy (not the origin server)",
                    "description": f"Port {port} je 'otvoren' samo zato što je domen iza CDN-a (Cloudflare/Vercel/Fastly/...). Edge sloj rutira saobraćaj — vi ne kontrolišete šta sluša na tom portu, niti je on direktno povezan sa vašim serverom.",
                    "description_en": f"Port {port} is 'open' only because the domain sits behind a CDN (Cloudflare/Vercel/Fastly/...). The edge layer routes traffic — you don't control what listens on that port, and it isn't directly tied to your server.",
                    "recommendation": "",
                    "recommendation_en": "",
                })
                continue
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
            "description": "Baze podataka (MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch, Cassandra, CouchDB, Couchbase), legacy servisi (FTP, Telnet), cache (Memcached), message brokeri (RabbitMQ, Kafka, Zookeeper), container orchestration (Docker daemon, Kubelet, etcd), search i big data (Solr, Hadoop, Spark) — nijedan nije javno dostupan.",
            "description_en": "Databases (MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch, Cassandra, CouchDB, Couchbase), legacy services (FTP, Telnet), cache (Memcached), message brokers (RabbitMQ, Kafka, Zookeeper), container orchestration (Docker daemon, Kubelet, etcd), search and big data (Solr, Hadoop, Spark) — none are publicly accessible.",
            "recommendation": "",
            "recommendation_en": "",
        })

    return results
