"""
Network Exposure Module
Verifica porte esposte e servizi accessibili pubblicamente
"""
import socket
from typing import List, Dict, Any
from ..models.schemas import Finding


# Porte comuni da verificare
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB"
}

# Porte considerate ad alto rischio se esposte
HIGH_RISK_PORTS = {23, 3389, 5900, 445, 21}


class NetworkScanner:
    """Scanner per l'esposizione di rete"""
    
    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout
    
    def scan(self, target: str) -> Dict[str, Any]:
        """
        Esegue la scansione delle porte
        
        Args:
            target: IP o hostname da scansionare
            
        Returns:
            Dict con risultati e findings
        """
        findings = []
        open_ports = []
        
        # Risolvi hostname a IP se necessario
        try:
            ip_address = socket.gethostbyname(target)
        except socket.gaierror:
            return {
                "status": "failed",
                "findings": [Finding(
                    category="Network",
                    severity="high",
                    title="Impossibile risolvere l'hostname",
                    description=f"Non è stato possibile risolvere {target} in un indirizzo IP",
                    score_impact=20
                )],
                "metadata": {"error": "DNS resolution failed"}
            }
        
        # Scansiona porte comuni
        for port, service in COMMON_PORTS.items():
            if self._check_port(ip_address, port):
                open_ports.append({"port": port, "service": service})
                
                # Genera finding basato sul tipo di porta
                finding = self._generate_finding(port, service, target)
                if finding:
                    findings.append(finding)
        
        # Finding generale se troppe porte esposte
        if len(open_ports) > 5:
            findings.append(Finding(
                category="Network",
                severity="moderate",
                title="Superficie di attacco elevata",
                description=f"Rilevate {len(open_ports)} porte aperte. Più servizi esposti aumentano la superficie di attacco.",
                evidence=f"Porte aperte: {', '.join([str(p['port']) for p in open_ports])}",
                impact="Ogni servizio esposto rappresenta un potenziale punto d'ingresso per attaccanti",
                recommendation="Chiudere porte non necessarie e limitare l'accesso tramite firewall",
                score_impact=15
            ))
        
        return {
            "status": "success",
            "findings": findings,
            "metadata": {
                "ip_address": ip_address,
                "total_ports_scanned": len(COMMON_PORTS),
                "open_ports": open_ports,
                "high_risk_exposed": len([p for p in open_ports if p['port'] in HIGH_RISK_PORTS])
            }
        }
    
    def _check_port(self, ip: str, port: int) -> bool:
        """Verifica se una porta è aperta"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _generate_finding(self, port: int, service: str, target: str) -> Finding:
        """Genera un finding basato sulla porta esposta"""
        
        # Porte ad alto rischio
        if port in HIGH_RISK_PORTS:
            severity_map = {
                23: ("critical", "Telnet non cifrato", "Telnet trasmette credenziali in chiaro", 25),
                3389: ("high", "RDP esposto pubblicamente", "Remote Desktop può essere bersaglio di brute force", 20),
                5900: ("high", "VNC esposto pubblicamente", "VNC spesso ha autenticazione debole", 18),
                445: ("high", "SMB esposto pubblicamente", "SMB è vettore comune di ransomware e exploit", 22),
                21: ("moderate", "FTP esposto", "FTP può trasmettere credenziali in chiaro", 12)
            }
            
            sev, title, desc, score = severity_map.get(port, ("moderate", f"{service} esposto", "", 10))
            
            return Finding(
                category="Network",
                severity=sev,
                title=title,
                description=desc,
                evidence=f"{service} (porta {port}) accessibile su {target}",
                impact="Accesso non autorizzato, furto credenziali, movimento laterale",
                recommendation=f"Chiudere porta {port} o limitare accesso tramite VPN/firewall",
                score_impact=score
            )
        
        # Porte database
        if port in {3306, 5432, 6379, 27017}:
            return Finding(
                category="Network",
                severity="high",
                title=f"Database {service} esposto pubblicamente",
                description=f"Il database {service} è accessibile da Internet",
                evidence=f"{service} (porta {port}) raggiungibile su {target}",
                impact="Accesso diretto ai dati, possibile data breach",
                recommendation=f"Chiudere porta {port} e consentire accesso solo da IP autorizzati",
                score_impact=20
            )
        
        # Nessun finding critico per HTTP/HTTPS standard
        if port in {80, 443}:
            return None
        
        return None
