"""
Domain Intelligence Module
Analizza informazioni sul dominio (età, DNS, infrastruttura)
"""
import dns.resolver
import socket
from datetime import datetime
from typing import Dict, Any, List
from ..models.schemas import Finding


class DomainScanner:
    """Scanner per domain intelligence"""
    
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
    
    def scan(self, target: str) -> Dict[str, Any]:
        """
        Esegue analisi del dominio
        
        Args:
            target: Dominio da analizzare
            
        Returns:
            Dict con risultati e findings
        """
        findings = []
        metadata = {}
        
        # Skip se è un IP
        if self._is_ip(target):
            return {
                "status": "skipped",
                "findings": [],
                "metadata": {"reason": "Target è un indirizzo IP, non un dominio"}
            }
        
        # Verifica risoluzione DNS
        dns_result = self._check_dns(target)
        metadata.update(dns_result)
        
        if not dns_result.get("resolved"):
            findings.append(Finding(
                category="Domain",
                severity="critical",
                title="Dominio non risolve",
                description=f"Il dominio {target} non è risolvibile via DNS",
                evidence=dns_result.get("error", "DNS resolution failed"),
                impact="Servizio non raggiungibile",
                recommendation="Verificare configurazione DNS del dominio",
                score_impact=30
            ))
            return {
                "status": "completed",
                "findings": findings,
                "metadata": metadata
            }
        
        # Controllo coerenza DNS
        if dns_result.get("multiple_ips") and len(dns_result.get("ip_addresses", [])) > 10:
            findings.append(Finding(
                category="Domain",
                severity="low",
                title="Molti record DNS A",
                description=f"Il dominio risolve a {len(dns_result['ip_addresses'])} indirizzi IP diversi",
                evidence=f"IP addresses: {', '.join(dns_result['ip_addresses'][:5])}...",
                impact="Possibile segno di CDN o infrastruttura complessa",
                recommendation="Normale per CDN, verificare se intenzionale",
                score_impact=2
            ))
        
        # Verifica presenza record di sicurezza (CAA)
        caa_result = self._check_caa(target)
        metadata["caa_present"] = caa_result["present"]
        
        if not caa_result["present"]:
            findings.append(Finding(
                category="Domain",
                severity="low",
                title="Record CAA non configurato",
                description="Il dominio non ha record CAA per controllare emissione certificati",
                evidence="Nessun record CAA trovato",
                impact="Chiunque può richiedere certificati TLS per questo dominio",
                recommendation="Configurare record CAA per limitare CA autorizzate",
                score_impact=5
            ))
        
        # Verifica DNSSEC
        dnssec_result = self._check_dnssec(target)
        metadata["dnssec_enabled"] = dnssec_result["enabled"]
        
        if not dnssec_result["enabled"]:
            findings.append(Finding(
                category="Domain",
                severity="moderate",
                title="DNSSEC non abilitato",
                description="Il dominio non ha DNSSEC configurato",
                evidence="Nessun record DNSKEY trovato",
                impact="Vulnerabile a DNS poisoning e spoofing",
                recommendation="Abilitare DNSSEC per il dominio",
                score_impact=10
            ))
        
        return {
            "status": "success",
            "findings": findings,
            "metadata": metadata
        }
    
    def _is_ip(self, target: str) -> bool:
        """Verifica se il target è un indirizzo IP"""
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            return False
    
    def _check_dns(self, domain: str) -> Dict[str, Any]:
        """Verifica risoluzione DNS"""
        result = {
            "resolved": False,
            "ip_addresses": [],
            "multiple_ips": False,
            "error": None
        }
        
        try:
            answers = dns.resolver.resolve(domain, 'A', lifetime=self.timeout)
            result["resolved"] = True
            result["ip_addresses"] = [str(rdata) for rdata in answers]
            result["multiple_ips"] = len(result["ip_addresses"]) > 1
        except dns.resolver.NXDOMAIN:
            result["error"] = "Dominio non esistente (NXDOMAIN)"
        except dns.resolver.NoAnswer:
            result["error"] = "Nessuna risposta DNS"
        except dns.resolver.Timeout:
            result["error"] = "Timeout DNS"
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def _check_caa(self, domain: str) -> Dict[str, Any]:
        """Verifica presenza record CAA"""
        result = {"present": False, "records": []}
        
        try:
            answers = dns.resolver.resolve(domain, 'CAA', lifetime=self.timeout)
            result["present"] = True
            result["records"] = [str(rdata) for rdata in answers]
        except:
            pass
        
        return result
    
    def _check_dnssec(self, domain: str) -> Dict[str, Any]:
        """Verifica se DNSSEC è abilitato"""
        result = {"enabled": False}
        
        try:
            # Cerca record DNSKEY
            answers = dns.resolver.resolve(domain, 'DNSKEY', lifetime=self.timeout)
            if answers:
                result["enabled"] = True
        except:
            pass
        
        return result
