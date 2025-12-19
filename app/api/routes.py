"""
API Routes - Exposure One REST API
"""
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from ..models.schemas import ScanRequest, ScanResponse
from ..core.scanner import Scanner

router = APIRouter()
scanner = Scanner()


@router.get("/")
async def root():
    """Health check endpoint"""
    return {
        "service": "Exposure One",
        "version": "1.0.0",
        "status": "operational",
        "description": "Attack Surface Discovery & Misconfiguration Assessment"
    }


@router.post("/api/scan", response_model=ScanResponse)
async def scan_target(request: ScanRequest):
    """
    Esegue una scansione completa di un target
    
    Args:
        request: ScanRequest con il target da scansionare
        
    Returns:
        ScanResponse con tutti i risultati della scansione
        
    Raises:
        HTTPException: Se la scansione fallisce
    """
    try:
        result = scanner.scan(request.target)
        return result
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Errore durante la scansione: {str(e)}"
        )


@router.get("/api/health")
async def health_check():
    """Endpoint per verificare lo stato del servizio"""
    return {
        "status": "healthy",
        "modules": {
            "network": "operational",
            "tls": "operational",
            "headers": "operational",
            "domain": "operational",
            "email": "operational"
        }
    }
