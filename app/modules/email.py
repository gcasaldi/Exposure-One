"""
Email Security Module
Analizza configurazione SPF, DKIM, DMARC per la protezione anti-spoofing
"""
import dns.resolver
from typing import Dict, Any, List
from ..models.schemas import Finding


class EmailSecurityScanner:
    """Scanner per email security posture"""
    
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
    
    def scan(self, target: str) -> Dict[str, Any]:
        """
        Esegue analisi email security
        
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
                "metadata": {"reason": "Target è un IP, email security non applicabile"}
            }
        
        # Verifica SPF
        spf_result = self._check_spf(target)
        metadata["spf"] = spf_result
        
        if not spf_result["present"]:
            findings.append(Finding(
                category="Email Security",
                severity="high",
                title="SPF non configurato",
                description="Il dominio non ha un record SPF configurato",
                evidence="Nessun record TXT SPF trovato",
                impact="Attaccanti possono inviare email spoofate dal dominio",
                recommendation="Configurare record SPF (TXT) con i server autorizzati",
                score_impact=15
            ))
        elif spf_result.get("too_permissive"):
            findings.append(Finding(
                category="Email Security",
                severity="moderate",
                title="SPF troppo permissivo",
                description="Il record SPF consente troppi mittenti",
                evidence=f"SPF: {spf_result.get('record', '')}",
                impact="Ridotta protezione anti-spoofing",
                recommendation="Restringere il record SPF ai soli server necessari",
                score_impact=8
            ))
        
        # Verifica DMARC
        dmarc_result = self._check_dmarc(target)
        metadata["dmarc"] = dmarc_result
        
        if not dmarc_result["present"]:
            findings.append(Finding(
                category="Email Security",
                severity="high",
                title="DMARC non configurato",
                description="Il dominio non ha una policy DMARC",
                evidence="Nessun record DMARC trovato su _dmarc." + target,
                impact="Nessuna policy su come gestire email non autenticate",
                recommendation="Configurare DMARC con policy reject/quarantine",
                score_impact=18
            ))
        else:
            # Analizza policy DMARC
            policy = dmarc_result.get("policy", "none")
            if policy == "none":
                findings.append(Finding(
                    category="Email Security",
                    severity="moderate",
                    title="DMARC in modalità monitor (p=none)",
                    description="DMARC configurato ma con policy 'none' (solo monitoring)",
                    evidence=f"DMARC policy: {policy}",
                    impact="Email spoofate non vengono bloccate",
                    recommendation="Passare a policy 'quarantine' o 'reject'",
                    score_impact=10
                ))
        
        # MX record check
        mx_result = self._check_mx(target)
        metadata["mx"] = mx_result
        
        if not mx_result["present"]:
            findings.append(Finding(
                category="Email Security",
                severity="low",
                title="Nessun record MX",
                description="Il dominio non ha record MX configurati",
                evidence="Nessun MX record trovato",
                impact="Il dominio non può ricevere email",
                recommendation="Normale se il dominio non gestisce email",
                score_impact=0
            ))
        
        # Se mancano sia SPF che DMARC - finding critico
        if not spf_result["present"] and not dmarc_result["present"]:
            findings.append(Finding(
                category="Email Security",
                severity="critical",
                title="Protezione email completamente assente",
                description="Nessuna protezione anti-spoofing configurata (né SPF né DMARC)",
                evidence="SPF e DMARC entrambi assenti",
                impact="Il dominio è altamente vulnerabile a phishing e spoofing",
                recommendation="PRIORITÀ: Configurare immediatamente SPF e DMARC",
                score_impact=25
            ))
        
        return {
            "status": "success",
            "findings": findings,
            "metadata": metadata
        }
    
    def _is_ip(self, target: str) -> bool:
        """Verifica se è un IP"""
        import socket
        try:
            socket.inet_aton(target)
            return True
        except:
            return False
    
    def _check_spf(self, domain: str) -> Dict[str, Any]:
        """Verifica record SPF"""
        result = {"present": False, "record": None, "too_permissive": False}
        
        try:
            answers = dns.resolver.resolve(domain, 'TXT', lifetime=self.timeout)
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith('v=spf1'):
                    result["present"] = True
                    result["record"] = txt
                    
                    # Verifica se troppo permissivo
                    if '+all' in txt or '?all' in txt:
                        result["too_permissive"] = True
                    break
        except:
            pass
        
        return result
    
    def _check_dmarc(self, domain: str) -> Dict[str, Any]:
        """Verifica record DMARC"""
        result = {"present": False, "record": None, "policy": None}
        
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = dns.resolver.resolve(dmarc_domain, 'TXT', lifetime=self.timeout)
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith('v=DMARC1'):
                    result["present"] = True
                    result["record"] = txt
                    
                    # Estrai policy
                    if 'p=' in txt:
                        policy_part = txt.split('p=')[1].split(';')[0].strip()
                        result["policy"] = policy_part
                    break
        except:
            pass
        
        return result
    
    def _check_mx(self, domain: str) -> Dict[str, Any]:
        """Verifica record MX"""
        result = {"present": False, "servers": []}
        
        try:
            answers = dns.resolver.resolve(domain, 'MX', lifetime=self.timeout)
            result["present"] = True
            result["servers"] = [str(rdata.exchange) for rdata in answers]
        except:
            pass
        
        return result
