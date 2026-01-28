"""
FastAPI Application Entry Point
Main application setup with middleware and configuration
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from app.api import router

# Create FastAPI application
app = FastAPI(
    title="Phish-Shield API",
    description="Multi-layered phishing detection system API",
    version="1.0.0"
)

# Configure CORS to allow browser extension to communicate
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "chrome-extension://*",  # Allow all Chrome extensions
        "http://localhost:*",     # Allow local development
        "http://127.0.0.1:*"      # Allow local development
    ],
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)

# Include API routes
app.include_router(router)

@app.get("/")
async def root():
    """Root endpoint - API health check"""
    return {
        "status": "online",
        "message": "Phish-Shield API is running",
        "version": "1.0.0"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}

if __name__ == "__main__":
    # Run the application
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,  # Auto-reload on code changes (development only)
        log_level="info"
    )