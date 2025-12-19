"""
Scanner Orchestrator
Coordina l'esecuzione di tutti i moduli di scanning
"""
import time
import uuid
from datetime import datetime
from typing import List, Dict, Any
from ..models.schemas import (
    ModuleResult, 
    Finding, 
    ScanResponse,
    ExecutiveSummary,
    TechnicalDetails
)
from ..modules import (
    NetworkScanner,
    TLSScanner,
    HeadersScanner,
    DomainScanner,
    EmailSecurityScanner
)
from .risk_scorer import RiskScorer


class Scanner:
    """Orchestrator principale per le scansioni"""
    
    def __init__(self):
        self.network_scanner = NetworkScanner()
        self.tls_scanner = TLSScanner()
        self.headers_scanner = HeadersScanner()
        self.domain_scanner = DomainScanner()
        self.email_scanner = EmailSecurityScanner()
        self.risk_scorer = RiskScorer()
    
    def scan(self, target: str) -> ScanResponse:
        """
        Esegue una scansione completa del target
        
        Args:
            target: Dominio o IP da scansionare
            
        Returns:
            ScanResponse con tutti i risultati
        """
        scan_id = str(uuid.uuid4())[:8]
        timestamp = datetime.utcnow().isoformat() + "Z"
        start_time = time.time()
        
        # Esegui tutti i moduli
        modules_results = []
        all_findings = []
        
        # 1. Network Exposure
        network_result = self._run_module(
            "Network Exposure",
            self.network_scanner.scan,
            target
        )
        modules_results.append(network_result)
        all_findings.extend(network_result.findings)
        
        # 2. TLS Security
        tls_result = self._run_module(
            "TLS Security",
            self.tls_scanner.scan,
            target
        )
        modules_results.append(tls_result)
        all_findings.extend(tls_result.findings)
        
        # 3. HTTP Headers
        headers_result = self._run_module(
            "HTTP Security Headers",
            self.headers_scanner.scan,
            target
        )
        modules_results.append(headers_result)
        all_findings.extend(headers_result.findings)
        
        # 4. Domain Intelligence
        domain_result = self._run_module(
            "Domain Intelligence",
            self.domain_scanner.scan,
            target
        )
        modules_results.append(domain_result)
        all_findings.extend(domain_result.findings)
        
        # 5. Email Security
        email_result = self._run_module(
            "Email Security",
            self.email_scanner.scan,
            target
        )
        modules_results.append(email_result)
        all_findings.extend(email_result.findings)
        
        # Calcola risk score
        risk_score = self.risk_scorer.calculate_score(all_findings)
        
        # Genera Executive View
        executive_view = self._generate_executive_view(
            target, risk_score, all_findings, timestamp
        )
        
        # Genera Technical View
        technical_view = self._generate_technical_view(
            modules_results, all_findings
        )
        
        scan_duration = time.time() - start_time
        
        return ScanResponse(
            target=target,
            scan_id=scan_id,
            timestamp=timestamp,
            risk_score=risk_score,
            executive_view=executive_view,
            technical_view=technical_view,
            scan_duration=round(scan_duration, 2)
        )
    
    def _run_module(self, module_name: str, scan_func, target: str) -> ModuleResult:
        """Esegue un singolo modulo di scanning con error handling"""
        start_time = time.time()
        
        try:
            result = scan_func(target)
            execution_time = time.time() - start_time
            
            return ModuleResult(
                module_name=module_name,
                status=result.get("status", "success"),
                findings=result.get("findings", []),
                metadata=result.get("metadata", {}),
                execution_time=round(execution_time, 2)
            )
        
        except Exception as e:
            execution_time = time.time() - start_time
            
            return ModuleResult(
                module_name=module_name,
                status="failed",
                findings=[Finding(
                    category=module_name,
                    severity="high",
                    title=f"Errore durante scansione {module_name}",
                    description=str(e),
                    score_impact=0
                )],
                metadata={"error": str(e)},
                execution_time=round(execution_time, 2)
            )
    
    def _generate_executive_view(
        self,
        target: str,
        risk_score,
        findings: List[Finding],
        timestamp: str
    ) -> ExecutiveSummary:
        """Genera la vista Executive (management-oriented)"""
        
        top_risks = self.risk_scorer.get_top_risks(findings, limit=3)
        recommendations = self.risk_scorer.get_recommendations(findings, limit=3)
        
        # Se non ci sono top risks, messaggio positivo
        if not top_risks:
            top_risks = ["✓ Nessun rischio critico identificato"]
        
        if not recommendations:
            recommendations = ["✓ Mantenere le attuali best practice di sicurezza"]
        
        return ExecutiveSummary(
            exposure_score=risk_score.total_score,
            risk_level=risk_score.risk_level,
            top_risks=top_risks,
            recommendations=recommendations,
            scan_timestamp=timestamp,
            target=target
        )
    
    def _generate_technical_view(
        self,
        modules_results: List[ModuleResult],
        all_findings: List[Finding]
    ) -> TechnicalDetails:
        """Genera la vista Technical (analyst-oriented)"""
        
        # Conta finding per severità
        findings_by_severity = {
            "critical": 0,
            "high": 0,
            "moderate": 0,
            "low": 0
        }
        
        for finding in all_findings:
            severity = finding.severity.lower()
            if severity in findings_by_severity:
                findings_by_severity[severity] += 1
        
        # Execution summary
        total_modules = len(modules_results)
        successful = len([m for m in modules_results if m.status == "success"])
        failed = len([m for m in modules_results if m.status == "failed"])
        skipped = len([m for m in modules_results if m.status == "skipped"])
        
        execution_summary = {
            "total_modules": total_modules,
            "successful": successful,
            "failed": failed,
            "skipped": skipped,
            "total_execution_time": round(sum(m.execution_time for m in modules_results), 2)
        }
        
        return TechnicalDetails(
            modules_results=modules_results,
            total_findings=len(all_findings),
            findings_by_severity=findings_by_severity,
            execution_summary=execution_summary
        )
