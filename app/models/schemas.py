"""
Exposure One - Data Models and Schemas
"""
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
from enum import Enum
import ipaddress
import re


class RiskLevel(str, Enum):
    """Livelli di rischio"""
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


class ScanRequest(BaseModel):
    """Request model per la scansione"""
    target: str = Field(..., description="Dominio o IP da scansionare")
    
    @validator('target')
    def validate_target(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError("Target non può essere vuoto")
        value = v.strip()
        # Consenti solo hostname o IP, evita URL completi e input con path/query
        if '://' in value or '/' in value:
            raise ValueError("Fornire solo dominio o IP, non un URL completo")
        # IP valido
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            pass
        # Hostname RFC1123 base (no caratteri speciali, lunghezza limitata)
        hostname_regex = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")
        if not hostname_regex.match(value):
            raise ValueError("Dominio non valido")
        return value


class Finding(BaseModel):
    """Singolo finding di sicurezza"""
    category: str
    severity: str
    title: str
    description: str
    evidence: Optional[str] = None
    impact: Optional[str] = None
    recommendation: Optional[str] = None
    score_impact: int = Field(default=0, ge=0, le=100)


class ModuleResult(BaseModel):
    """Risultato di un modulo di scanning"""
    module_name: str
    status: str  # success, failed, skipped
    findings: List[Finding] = []
    metadata: Dict[str, Any] = {}
    execution_time: float = 0.0


class RiskScore(BaseModel):
    """Risk score e classificazione"""
    total_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    category_scores: Dict[str, int] = {}


class ExecutiveSummary(BaseModel):
    """Vista Executive - sintesi per management"""
    exposure_score: int
    risk_level: RiskLevel
    top_risks: List[str]
    recommendations: List[str]
    scan_timestamp: str
    target: str


class TechnicalDetails(BaseModel):
    """Vista Technical - dettagli per security analyst"""
    modules_results: List[ModuleResult]
    total_findings: int
    findings_by_severity: Dict[str, int]
    execution_summary: Dict[str, Any]


class ScanResponse(BaseModel):
    """Response completa della scansione"""
    target: str
    scan_id: str
    timestamp: str
    risk_score: RiskScore
    executive_view: ExecutiveSummary
    technical_view: TechnicalDetails
    scan_duration: float
