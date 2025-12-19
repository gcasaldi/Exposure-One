"""
HTTP Security Headers Module
Analizza la presenza e configurazione degli header di sicurezza HTTP
"""
import requests
import os
from typing import Dict, Any, List
from ..models.schemas import Finding


# Header di sicurezza critici
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "high",
        "score": 15,
        "description": "HSTS protegge da downgrade attack forzando HTTPS"
    },
    "Content-Security-Policy": {
        "severity": "high",
        "score": 18,
        "description": "CSP previene XSS e injection attack"
    },
    "X-Frame-Options": {
        "severity": "moderate",
        "score": 10,
        "description": "Protegge da clickjacking"
    },
    "X-Content-Type-Options": {
        "severity": "moderate",
        "score": 8,
        "description": "Previene MIME-sniffing attack"
    },
    "Referrer-Policy": {
        "severity": "low",
        "score": 5,
        "description": "Controlla informazioni inviate nel referrer"
    },
    "Permissions-Policy": {
        "severity": "low",
        "score": 5,
        "description": "Controlla accesso a feature del browser"
    }
}


class HeadersScanner:
    """Scanner per HTTP security headers"""
    
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
    
    def scan(self, target: str) -> Dict[str, Any]:
        """
        Esegue la scansione degli header HTTP
        
        Args:
            target: Hostname o URL da scansionare
            
        Returns:
            Dict con risultati e findings
        """
        findings = []
        metadata = {}
        
        # Normalizza target a URL
        if not target.startswith(('http://', 'https://')):
            url = f"https://{target}"
        else:
            url = target
        
        # Esegui richiesta HTTP
        try:
            response = requests.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False  # Per testing, ignora certificati invalidi
            )
            headers = response.headers
            metadata["status_code"] = response.status_code
            metadata["final_url"] = response.url
            
        except requests.RequestException as e:
            # Prova con HTTP se HTTPS fallisce
            if url.startswith('https://'):
                try:
                    url = url.replace('https://', 'http://')
                    response = requests.get(url, timeout=self.timeout, allow_redirects=True)
                    headers = response.headers
                    metadata["status_code"] = response.status_code
                    metadata["final_url"] = response.url
                    metadata["https_failed"] = True
                except:
                    return {
                        "status": "failed",
                        "findings": [Finding(
                            category="HTTP Headers",
                            severity="high",
                            title="Server non raggiungibile via HTTP/HTTPS",
                            description=f"Impossibile connettersi a {target}",
                            score_impact=15
                        )],
                        "metadata": {"error": str(e)}
                    }
            else:
                return {
                    "status": "failed",
                    "findings": [],
                    "metadata": {"error": str(e)}
                }
        
        # Analizza header di sicurezza
        missing_headers = []
        weak_headers = []
        present_headers = []
        
        for header, config in SECURITY_HEADERS.items():
            if header in headers:
                present_headers.append(header)
                # Analizza valore header
                value = headers[header]
                weakness = self._check_header_weakness(header, value)
                if weakness:
                    weak_headers.append((header, weakness, config))
            else:
                missing_headers.append((header, config))
        
        metadata["present_headers"] = present_headers
        metadata["missing_count"] = len(missing_headers)
        metadata["weak_count"] = len(weak_headers)
        
        # Genera findings per header mancanti
        for header, config in missing_headers:
            findings.append(Finding(
                category="HTTP Headers",
                severity=config["severity"],
                title=f"Header di sicurezza mancante: {header}",
                description=config["description"],
                evidence=f"Header '{header}' non presente nella risposta HTTP",
                impact="Esposizione a attacchi che questo header previene",
                recommendation=f"Aggiungere header '{header}' alla configurazione del server",
                score_impact=config["score"]
            ))
        
        # Genera findings per header deboli
        for header, weakness, config in weak_headers:
            findings.append(Finding(
                category="HTTP Headers",
                severity="moderate",
                title=f"Configurazione debole: {header}",
                description=weakness,
                evidence=f"{header}: {headers[header]}",
                recommendation=f"Rafforzare configurazione di '{header}'",
                score_impact=config["score"] // 2
            ))
        
        # Header problematici se presenti
        if "Server" in headers:
            findings.append(Finding(
                category="HTTP Headers",
                severity="low",
                title="Server header espone informazioni",
                description="L'header 'Server' rivela informazioni sul software utilizzato",
                evidence=f"Server: {headers['Server']}",
                impact="Information disclosure che può aiutare attaccanti",
                recommendation="Rimuovere o offuscare header 'Server'",
                score_impact=3
            ))
        
        if "X-Powered-By" in headers:
            findings.append(Finding(
                category="HTTP Headers",
                severity="low",
                title="X-Powered-By espone tecnologia",
                description="L'header 'X-Powered-By' rivela la tecnologia backend",
                evidence=f"X-Powered-By: {headers['X-Powered-By']}",
                impact="Information disclosure",
                recommendation="Rimuovere header 'X-Powered-By'",
                score_impact=2
            ))
        
        return {
            "status": "success",
            "findings": findings,
            "metadata": metadata
        }

    @staticmethod
    def _get_bool_env(var_name: str, default: bool = False) -> bool:
        value = os.getenv(var_name)
        if value is None:
            return default
        return value.strip().lower() in {"1", "true", "yes", "on"}
    
    def _check_header_weakness(self, header: str, value: str) -> str:
        """Verifica se un header ha configurazione debole"""
        value_lower = value.lower()
        
        if header == "Strict-Transport-Security":
            if "max-age" not in value_lower:
                return "HSTS senza max-age"
            # Estrai max-age
            try:
                max_age = int(value.split('max-age=')[1].split(';')[0].split(',')[0])
                if max_age < 31536000:  # 1 anno
                    return f"HSTS max-age troppo basso ({max_age}s, consigliato >= 31536000)"
            except:
                pass
        
        elif header == "Content-Security-Policy":
            if "unsafe-inline" in value_lower or "unsafe-eval" in value_lower:
                return "CSP contiene direttive 'unsafe' che riducono la protezione"
        
        elif header == "X-Frame-Options":
            if value_lower not in ["deny", "sameorigin"]:
                return f"Valore X-Frame-Options debole: '{value}'"
        
        return None
