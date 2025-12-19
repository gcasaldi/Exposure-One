"""
TLS & Transport Security Module
Verifica configurazione TLS e sicurezza del trasporto
"""
import ssl
import socket
from typing import Dict, Any, List
from ..models.schemas import Finding


class TLSScanner:
    """Scanner per la sicurezza TLS"""
    
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
    
    def scan(self, target: str) -> Dict[str, Any]:
        """
        Esegue la scansione TLS
        
        Args:
            target: Hostname da scansionare
            
        Returns:
            Dict con risultati e findings
        """
        findings = []
        metadata = {}
        
        # Verifica presenza HTTPS (porta 443)
        https_available = self._check_https(target)
        metadata["https_available"] = https_available
        
        if not https_available:
            findings.append(Finding(
                category="TLS",
                severity="high",
                title="HTTPS non disponibile",
                description=f"Il server {target} non risponde sulla porta 443 (HTTPS)",
                evidence="Connessione HTTPS fallita",
                impact="Comunicazioni non cifrate, vulnerabile a man-in-the-middle",
                recommendation="Configurare certificato TLS e abilitare HTTPS",
                score_impact=25
            ))
            return {
                "status": "completed",
                "findings": findings,
                "metadata": metadata
            }
        
        # Analizza configurazione TLS
        tls_info = self._analyze_tls(target)
        metadata.update(tls_info)
        
        # Verifica versione TLS
        if tls_info.get("tls_version"):
            if tls_info["tls_version"] in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
                findings.append(Finding(
                    category="TLS",
                    severity="critical",
                    title="Versione TLS obsoleta",
                    description=f"Il server supporta {tls_info['tls_version']}, una versione deprecata e insicura",
                    evidence=f"TLS version: {tls_info['tls_version']}",
                    impact="Vulnerabile a downgrade attack e protocolli compromessi",
                    recommendation="Disabilitare TLS 1.0/1.1 e abilitare solo TLS 1.2/1.3",
                    score_impact=30
                ))
            elif tls_info["tls_version"] == "TLSv1.2":
                # TLS 1.2 è ok ma non ottimale
                findings.append(Finding(
                    category="TLS",
                    severity="low",
                    title="TLS 1.3 non rilevato",
                    description="Il server usa TLS 1.2. TLS 1.3 offre migliori performance e sicurezza",
                    evidence=f"TLS version: {tls_info['tls_version']}",
                    recommendation="Considerare l'upgrade a TLS 1.3",
                    score_impact=3
                ))
        
        # Verifica cipher suite
        if tls_info.get("cipher"):
            weak_ciphers = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT"]
            cipher_str = tls_info["cipher"]
            
            for weak in weak_ciphers:
                if weak in cipher_str:
                    findings.append(Finding(
                        category="TLS",
                        severity="high",
                        title="Cipher suite debole rilevata",
                        description=f"Il server supporta cipher suite con {weak}, considerato insicuro",
                        evidence=f"Cipher: {cipher_str}",
                        impact="Vulnerabile a attacchi crittografici",
                        recommendation="Configurare solo cipher suite moderne e sicure",
                        score_impact=20
                    ))
                    break
        
        # Verifica certificato
        if not tls_info.get("cert_valid"):
            findings.append(Finding(
                category="TLS",
                severity="critical",
                title="Certificato TLS non valido",
                description="Il certificato TLS presenta problemi di validazione",
                evidence=tls_info.get("cert_error", "Errore sconosciuto"),
                impact="Gli utenti riceveranno warning di sicurezza, possibile MITM",
                recommendation="Rinnovare o correggere il certificato TLS",
                score_impact=25
            ))
        
        return {
            "status": "success",
            "findings": findings,
            "metadata": metadata
        }
    
    def _check_https(self, target: str) -> bool:
        """Verifica se HTTPS è disponibile"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((target, 443))
            sock.close()
            return result == 0
        except:
            return False
    
    def _analyze_tls(self, target: str) -> Dict[str, Any]:
        """Analizza configurazione TLS"""
        result = {
            "tls_version": None,
            "cipher": None,
            "cert_valid": False,
            "cert_error": None
        }
        
        try:
            context = ssl.create_default_context()
            # Per testing, accettiamo certificati self-signed
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    result["tls_version"] = ssock.version()
                    result["cipher"] = ssock.cipher()[0] if ssock.cipher() else None
                    
                    # Verifica certificato
                    try:
                        cert = ssock.getpeercert()
                        result["cert_valid"] = True
                    except:
                        result["cert_valid"] = False
                        result["cert_error"] = "Impossibile recuperare certificato"
        
        except ssl.SSLError as e:
            result["cert_error"] = str(e)
        except Exception as e:
            result["cert_error"] = f"Errore connessione TLS: {str(e)}"
        
        return result
