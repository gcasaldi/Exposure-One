"""
Exposure One - Main Application Entry Point
Attack Surface Discovery & Misconfiguration Assessment Tool
"""
import uvicorn
from fastapi import FastAPI
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

# CORS middleware per consentire richieste dal frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
