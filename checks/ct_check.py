"""
Certificate Transparency Check
Queries crt.sh to verify CT log coverage and detect unauthorized certificates.
"""
import requests
from typing import List, Dict, Any

TIMEOUT = 8


def run(domain: str) -> List[Dict[str, Any]]:
    results = []

    try:
        resp = requests.get(
            f"https://crt.sh/?q={domain}&output=json",
            timeout=TIMEOUT,
            headers={"User-Agent": "SecurityScanner/1.0"},
        )

        if resp.status_code == 200:
            certs = resp.json()
            cert_count = len(certs)

            # Collect unique issuers
            issuers = set()
            for c in certs[:100]:
                issuer = c.get("issuer_name", "")
                if issuer:
                    # Extract organization
                    for part in issuer.split(","):
                        part = part.strip()
                        if part.startswith("O="):
                            issuers.add(part[2:].strip())

            if cert_count > 0:
                results.append({
                    "id": "ct_logged",
                    "category": "Certificate Transparency",
                    "severity": "INFO",
                    "passed": True,
                    "title": f"CT logovi: {cert_count} sertifikata evidentirano",
                    "title_en": f"CT logs: {cert_count} certificates recorded",
                    "description": f"Sertifikati za {domain} su evidentirani u Certificate Transparency logovima. Izdava\u010di: {', '.join(list(issuers)[:3]) if issuers else 'N/A'}.",
                    "description_en": f"Certificates for {domain} are recorded in Certificate Transparency logs. Issuers: {', '.join(list(issuers)[:3]) if issuers else 'N/A'}.",
                    "recommendation": "",
                    "recommendation_en": "",
                })

                # Check for suspicious number of issuers (more than 3 different CAs)
                if len(issuers) > 3:
                    results.append({
                        "id": "ct_many_issuers",
                        "category": "Certificate Transparency",
                        "severity": "LOW",
                        "passed": False,
                        "title": f"Vi\u0161e razli\u010ditih CA izdava\u010da: {len(issuers)}",
                        "title_en": f"Multiple different CA issuers: {len(issuers)}",
                        "description": f"Prona\u0111eno {len(issuers)} razli\u010ditih sertifikacionih autoriteta koji su izdavali sertifikate za {domain}. Ovo mo\u017ee ukazivati na neovla\u0161\u0107eno izdavanje.",
                        "description_en": f"Found {len(issuers)} different certificate authorities that issued certificates for {domain}. This may indicate unauthorized issuance.",
                        "recommendation": "Proverite da li su svi izdava\u010di legitimni. Koristite CAA DNS record da ograni\u010dite izdava\u010de.",
                        "recommendation_en": "Verify all issuers are legitimate. Use CAA DNS record to restrict issuers.",
                    })
            else:
                results.append({
                    "id": "ct_not_found",
                    "category": "Certificate Transparency",
                    "severity": "MEDIUM",
                    "passed": False,
                    "title": "Sertifikat nije prona\u0111en u CT logovima",
                    "title_en": "Certificate not found in CT logs",
                    "description": "Nijedan sertifikat za ovaj domen nije evidentiran u Certificate Transparency logovima. Ovo je neobi\u010dno za sajtove sa HTTPS.",
                    "description_en": "No certificates for this domain are recorded in Certificate Transparency logs. This is unusual for HTTPS sites.",
                    "recommendation": "Koristite CA koji podrzava CT (Let's Encrypt, DigiCert, Sectigo).",
                    "recommendation_en": "Use a CA that supports CT (Let's Encrypt, DigiCert, Sectigo).",
                })
        else:
            # crt.sh unreachable - skip gracefully
            pass

    except requests.exceptions.Timeout:
        pass
    except Exception:
        pass

    return results
