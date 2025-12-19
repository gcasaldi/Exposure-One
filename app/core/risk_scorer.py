"""
Risk Scoring Engine
Calcola l'Exposure Score basato sui finding dei vari moduli
"""
from typing import List, Dict, Any
from ..models.schemas import Finding, RiskScore, RiskLevel


class RiskScorer:
    """Engine per il calcolo del risk score"""
    
    # Pesi per categoria (quanto conta ogni categoria nel totale)
    CATEGORY_WEIGHTS = {
        "Network": 0.25,
        "TLS": 0.25,
        "HTTP Headers": 0.20,
        "Domain": 0.10,
        "Email Security": 0.20
    }
    
    def calculate_score(self, all_findings: List[Finding]) -> RiskScore:
        """
        Calcola il risk score totale e per categoria
        
        Args:
            all_findings: Lista di tutti i finding dai vari moduli
            
        Returns:
            RiskScore con punteggio totale e breakdown per categoria
        """
        category_scores = {}
        
        # Calcola score per ogni categoria
        for category in self.CATEGORY_WEIGHTS.keys():
            category_findings = [f for f in all_findings if f.category == category]
            category_score = self._calculate_category_score(category_findings)
            category_scores[category] = category_score
        
        # Calcola score totale pesato
        total_score = 0
        for category, weight in self.CATEGORY_WEIGHTS.items():
            total_score += category_scores.get(category, 0) * weight
        
        total_score = int(min(100, max(0, total_score)))
        
        # Determina risk level
        risk_level = self._determine_risk_level(total_score)
        
        return RiskScore(
            total_score=total_score,
            risk_level=risk_level,
            category_scores=category_scores
        )
    
    def _calculate_category_score(self, findings: List[Finding]) -> int:
        """Calcola score per una singola categoria"""
        if not findings:
            return 0
        
        # Somma tutti gli score_impact con cap a 100
        total_impact = sum(f.score_impact for f in findings)
        
        # Normalizza a 0-100
        # Usiamo una curva logaritmica per evitare che troppi finding piccoli
        # contino quanto pochi finding gravi
        import math
        if total_impact == 0:
            return 0
        
        # Formula: score = min(100, impact * (1 + log(count)/5))
        # Più finding ci sono, più conta, ma non linearmente
        count_factor = 1 + (math.log(len(findings)) / 5)
        score = min(100, total_impact * count_factor * 0.8)
        
        return int(score)
    
    def _determine_risk_level(self, score: int) -> RiskLevel:
        """Determina il livello di rischio basato sul punteggio"""
        if score >= 76:
            return RiskLevel.CRITICAL
        elif score >= 51:
            return RiskLevel.HIGH
        elif score >= 26:
            return RiskLevel.MODERATE
        else:
            return RiskLevel.LOW
    
    def get_top_risks(self, findings: List[Finding], limit: int = 3) -> List[str]:
        """
        Estrae i principali rischi da comunicare in Executive View
        
        Args:
            findings: Lista di tutti i finding
            limit: Numero massimo di rischi da restituire
            
        Returns:
            Lista di stringhe descriventi i top risks
        """
        # Ordina per severità e score_impact
        severity_order = {"critical": 4, "high": 3, "moderate": 2, "low": 1}
        
        sorted_findings = sorted(
            findings,
            key=lambda f: (severity_order.get(f.severity, 0), f.score_impact),
            reverse=True
        )
        
        top_risks = []
        for finding in sorted_findings[:limit]:
            risk_str = f"{finding.title}"
            if finding.category:
                risk_str = f"[{finding.category}] {risk_str}"
            top_risks.append(risk_str)
        
        return top_risks
    
    def get_recommendations(self, findings: List[Finding], limit: int = 3) -> List[str]:
        """
        Estrae le raccomandazioni prioritarie per Executive View
        
        Args:
            findings: Lista di tutti i finding
            limit: Numero massimo di raccomandazioni
            
        Returns:
            Lista di raccomandazioni operative
        """
        # Ordina per severità e score_impact
        severity_order = {"critical": 4, "high": 3, "moderate": 2, "low": 1}
        
        sorted_findings = sorted(
            findings,
            key=lambda f: (severity_order.get(f.severity, 0), f.score_impact),
            reverse=True
        )
        
        recommendations = []
        seen = set()
        
        for finding in sorted_findings:
            if finding.recommendation and finding.recommendation not in seen:
                recommendations.append(finding.recommendation)
                seen.add(finding.recommendation)
                if len(recommendations) >= limit:
                    break
        
        return recommendations
