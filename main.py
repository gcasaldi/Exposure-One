"""
Exposure One - Main Application Entry Point
Attack Surface Discovery & Misconfiguration Assessment Tool
"""
import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router
import os

# Crea applicazione FastAPI
app = FastAPI(
    title="Exposure One",
    description="Attack Surface Discovery & Misconfiguration Assessment",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS configurabile da env (comma-separated), default restrittivo su localhost
raw_origins = os.getenv("ALLOW_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000")
allow_origins = [o.strip() for o in raw_origins.split(",") if o.strip()]

# CORS middleware per consentire richieste dal frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Aggiunge header di sicurezza basilari a tutte le risposte"""
    response: Response = await call_next(request)
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    response.headers.setdefault("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; frame-ancestors 'none'")
    return response

# Include API router
app.include_router(router)

# Serve static files (frontend)
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/")
    async def serve_frontend():
        """Serve la pagina principale del frontend"""
        index_path = os.path.join(static_dir, "index.html")
        if os.path.exists(index_path):
            return FileResponse(index_path)
        return {"message": "Frontend not found. API is available at /api/scan"}


if __name__ == "__main__":
    print("🎯 Starting Exposure One...")
    print("📊 Attack Surface Discovery & Misconfiguration Assessment")
    print("=" * 60)
    print("🌐 Server: http://localhost:8000")
    print("📖 API Docs: http://localhost:8000/docs")
    print("=" * 60)
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
