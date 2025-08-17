"""
Main application entry point.

This module initializes the FastAPI application, configures routes,
middleware, and static files.
"""
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

from src.api import incidents


# Initialize FastAPI application
app = FastAPI(
    title="HackAI Risk Management System",
    description="Sistema de gestión de riesgos e incidentes de ciberseguridad "
                "impulsado por IA",
    version="2.1.0-optimized"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="src/static"), name="static")

# Configure templates
templates = Jinja2Templates(directory="src/templates")

# Include unified API routes
app.include_router(incidents.router, prefix="/api", tags=["incidents"])


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """
    Render the main application page.
    
    Args:
        request (Request): The incoming request
        
    Returns:
        TemplateResponse: The rendered HTML template
    """
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "title": "HackAI - Gestión de Riesgos"}
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 