"""
Risk-Guardian API - Versión Limpia
Endpoints esenciales sin duplicaciones ni código redundante.
"""
from fastapi import APIRouter, HTTPException, BackgroundTasks, Query
from typing import Dict, Any
from datetime import datetime

from src.controllers.incident_controller import IncidentController
from src.models.models import AnalysisRequest
from src.utils.logger import setup_logger
from src.services.rag import search_security_knowledge, get_rag_service

logger = setup_logger(__name__)

# Router y controller
router = APIRouter()
controller = IncidentController()


# ============================================================================
# ENDPOINTS PRINCIPALES
# ============================================================================

@router.get("/examples", tags=["incidents"])
async def get_incident_examples():
    """Obtiene ejemplos de incidentes por categoría."""
    try:
        return await controller.get_incident_examples()
    except Exception as e:
        logger.error(f"Error en /examples: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze", tags=["incidents"])
async def analyze_incident(
    request: Dict[str, Any],
    background_tasks: BackgroundTasks,
    analysis_type: str = Query(
        default="estandar",
        description="Tipo: rapido, estandar, experto",
        regex="^(rapido|estandar|experto)$"
    )
):
    """
    Analiza incidente con LangChain + RAG + GPT-4.1.
    
    Body:
    - titulo: Título del incidente (requerido)
    - descripcion: Descripción detallada (requerido)
    - categoria_inicial: Categoría opcional
    - urgencia: Nivel de urgencia opcional
    - contexto_adicional: Información adicional opcional
    """
    try:
        return await controller.analyze_incident(
            incident_data=request,
            analysis_type=analysis_type,
            background_tasks=background_tasks
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error en /analyze: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/analysis-types", tags=["configuration"])
async def get_analysis_types():
    """Obtiene tipos de análisis disponibles y sus características."""
    try:
        return await controller.get_analysis_types()
    except Exception as e:
        logger.error(f"Error en /analysis-types: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# ENDPOINTS RAG (Sistema de Conocimiento)
# ============================================================================

@router.get("/rag/health", tags=["rag"])
async def rag_health_check():
    """Verifica estado del sistema RAG."""
    try:
        rag_service = await get_rag_service()
        return await rag_service.health_check()
    except Exception as e:
        logger.error(f"Error en RAG health: {str(e)}")
        return {"status": "error", "message": str(e)}


@router.post("/rag/search", tags=["rag"])
async def search_knowledge(
    query: str = Query(description="Consulta de búsqueda"),
    max_results: int = Query(default=5, ge=1, le=10)
):
    """Busca en la base de conocimiento de ciberseguridad."""
    try:
        results = await search_security_knowledge(query, max_results)
        return {
            "status": "success",
            "query": query,
            "results_count": len(results),
            "results": results,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error en búsqueda: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/rag/stats", tags=["rag"])
async def get_rag_stats():
    """Obtiene estadísticas del sistema RAG."""
    try:
        rag_service = await get_rag_service()
        stats = rag_service.get_stats()
        return {
            "status": "success",
            "statistics": stats,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error obteniendo estadísticas RAG: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# ESTADÍSTICAS CONSOLIDADAS (Delega al controlador)
# ============================================================================

@router.get("/system/stats", tags=["system"])
async def get_system_stats():
    """Obtiene estadísticas consolidadas del sistema completo."""
    try:
        return await controller.get_system_stats()
    except Exception as e:
        logger.error(f"Error en estadísticas del sistema: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))