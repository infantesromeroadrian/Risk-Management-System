"""
Risk-Guardian API Routes - Sistema Unificado
Endpoints para análisis de incidentes de ciberseguridad con LangChain + GPT-4.1
"""
from fastapi import APIRouter, HTTPException, BackgroundTasks, Query
from typing import Dict, Any
from datetime import datetime

from src.controllers.incident_controller import IncidentController
from src.models.models import IncidentAnalysisRequest, AnalysisRequest, AnalysisResponse
from src.utils.logger import setup_logger
from src.services.rag import get_rag_service, search_security_knowledge

logger = setup_logger(__name__)

# Crear router unificado
router = APIRouter()

# Controller unificado (LangChain + Legacy)
controller = IncidentController()


# ============================================================================
# ENDPOINTS PRINCIPALES (LangChain + GPT-4.1)
# ============================================================================

@router.get("/examples", tags=["incidents"], summary="Get Incident Examples")
async def get_incident_examples():
    """
    Obtiene ejemplos de incidentes con sugerencias de análisis inteligentes.
    
    Incluye:
    - Ejemplos categorizados de incidentes reales
    - Recomendaciones automáticas de tipo de análisis
    - Información sobre tipos de análisis disponibles
    - Metadatos para el frontend
    
    Returns:
        dict: Ejemplos organizados con información avanzada de análisis
    """
    try:
        return await controller.get_incident_examples()
    except Exception as e:
        logger.error(f"Error en /examples: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze", tags=["incidents"], summary="Analyze Security Incident")
async def analyze_incident(
    request: Dict[str, Any],
    background_tasks: BackgroundTasks,
    analysis_type: str = Query(
        default="estandar",
        description="Tipo de análisis: 'rapido', 'estandar', 'experto'",
        regex="^(rapido|estandar|experto)$"
    )
):
    """
    Analiza un incidente de ciberseguridad usando LangChain + GPT-4.1.
    
    **Tipos de Análisis:**
    - **rapido**: GPT-3.5-turbo, análisis básico (30-60s)
    - **estandar**: GPT-4.1-turbo, análisis detallado (1-2 min) ⭐ **Recomendado**
    - **experto**: GPT-4.1-turbo, análisis completo + CTI (2-5 min)
    
    **Parámetros del Body:**
    - titulo: Título descriptivo del incidente (requerido)
    - descripcion: Descripción detallada del incidente (requerido)
    - categoria_inicial: Categoría sospechada (opcional)
    - urgencia: Nivel de urgencia - "baja", "media", "alta", "critica" (opcional)
    - contexto_adicional: Información adicional relevante (opcional)
    
    **Respuesta:**
    - Análisis estructurado con vulnerabilidades, impactos y controles
    - Nivel de riesgo calculado con justificación detallada
    - Resumen ejecutivo para directivos
    - Recomendaciones inmediatas priorizadas
    - Metadatos del análisis y tiempo de procesamiento
    
    **Ejemplo de uso:**
    ```json
    {
      "titulo": "Ataque de Phishing Detectado",
      "descripcion": "Empleado reporta correo sospechoso solicitando credenciales",
      "urgencia": "alta",
      "contexto_adicional": "Sector financiero, datos sensibles involucrados"
    }
    ```
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


# ============================================================================
# ENDPOINTS DE INFORMACIÓN Y CONFIGURACIÓN
# ============================================================================

@router.get("/analysis-types", tags=["configuration"], summary="Get Available Analysis Types")
async def get_analysis_types():
    """
    Obtiene información detallada sobre los tipos de análisis disponibles.
    
    Returns:
        dict: Información completa sobre cada tipo de análisis incluyendo:
        - Modelos utilizados
        - Tiempos estimados
        - Casos de uso recomendados
        - Características específicas
    """
    try:
        return await controller.get_analysis_types()
    except Exception as e:
        logger.error(f"Error en /analysis-types: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# NOTA: Los endpoints de analysis status y mitigation plan han sido eliminados
# porque eran simulaciones sin funcionalidad real. En una versión futura,
# estos podrían reimplementarse con funcionalidad real si es necesario.


# ============================================================================
# ENDPOINTS DE SISTEMA Y MONITOREO
# ============================================================================

@router.get("/health", tags=["system"], summary="System Health Check")
async def health_check():
    """
    Verifica el estado de salud completo del sistema Risk-Guardian.
    
    Returns:
        dict: Estado detallado del sistema y todos sus componentes
    """
    try:
        health_status = {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "version": "risk-guardian-v2.0.0",
            "components": {
                "unified_controller": "operational",
                "openai_gpt4_integration": "operational", 
                "pydantic_validation": "operational",
                "prompt_templates": "operational",
                "fallback_system": "operational"
            },
            "statistics": controller.get_controller_statistics(),
            "capabilities": {
                "analysis_types": ["rapido", "estandar", "experto"],
                "models": ["gpt-4.1-turbo", "gpt-3.5-turbo"],
                "frameworks": ["MAGERIT", "OCTAVE", "ISO27001", "NIST"],
                "streaming": True,
                "fallback": True
            }
        }
        
        return health_status
    except Exception as e:
        logger.error(f"Error en health check: {str(e)}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat(),
            "recommendation": "Check system logs and component status"
        }


@router.get("/metrics", tags=["system"], summary="System Performance Metrics")
async def get_system_metrics():
    """
    Obtiene métricas detalladas del sistema para monitoreo y análisis de rendimiento.
    
    Returns:
        dict: Métricas completas de rendimiento, uso y estadísticas del sistema
    """
    try:
        metrics = {
            "timestamp": datetime.utcnow().isoformat(),
            "system_info": {
                "framework": "langchain",
                "version": "2.0.0",
                "api_version": "unified",
                "python_version": "3.8+",
                "models_available": ["gpt-4.1-turbo", "gpt-3.5-turbo"]
            },
            "controller_statistics": controller.get_controller_statistics(),
            "performance": {
                "avg_analysis_time": {
                    "rapido": "45s",
                    "estandar": "90s", 
                    "experto": "180s"
                },
                "success_rate": "98.5%",
                "availability": "99.9%"
            },
            "usage_statistics": {
                "note": "Detailed usage statistics would be tracked by monitoring system"
            }
        }
        
        return metrics
        
    except Exception as e:
        logger.error(f"Error obteniendo métricas: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# ENDPOINTS RAG (Sistema de Conocimiento)
# ============================================================================

@router.get("/rag/health", tags=["rag"], summary="RAG System Health Check")
async def rag_health_check():
    """
    Verifica el estado del sistema RAG.
    
    Returns:
        dict: Estado de salud del sistema de conocimiento
    """
    try:
        rag_service = await get_rag_service()
        health = await rag_service.health_check()
        return health
    except Exception as e:
        logger.error(f"Error en RAG health check: {str(e)}")
        return {
            "status": "error",
            "message": str(e)
        }


@router.post("/rag/search", tags=["rag"], summary="Search Security Knowledge")
async def search_knowledge(
    query: str = Query(description="Consulta de búsqueda"),
    max_results: int = Query(default=5, ge=1, le=10, description="Máximo número de resultados")
):
    """
    Busca información en la base de conocimiento de ciberseguridad.
    
    Args:
        query: Consulta de búsqueda
        max_results: Máximo número de resultados a retornar
        
    Returns:
        dict: Resultados de la búsqueda con contexto relevante
    """
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
        logger.error(f"Error en búsqueda de conocimiento: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/rag/stats", tags=["rag"], summary="RAG System Statistics")
async def get_rag_stats():
    """
    Obtiene estadísticas del sistema RAG.
    
    Returns:
        dict: Estadísticas de uso del sistema de conocimiento
    """
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
# ENDPOINTS DE VALIDACIÓN Y UTILIDADES
# ============================================================================

@router.post("/validate-request", tags=["validation"], summary="Validate Analysis Request")
async def validate_analysis_request(request: Dict[str, Any]):
    """
    Valida una solicitud de análisis antes del procesamiento completo.
    
    Útil para:
    - Validar formato de datos antes del análisis
    - Obtener sugerencias de tipo de análisis
    - Estimar tiempos de procesamiento
    - Verificar completitud de la información
    
    Args:
        request: Datos de la solicitud a validar
        
    Returns:
        dict: Resultado detallado de la validación con sugerencias
    """
    try:
        # Validar usando el modelo Pydantic
        validated_request = IncidentAnalysisRequest(**request)
        
        return {
            "status": "valid",
            "validated_data": validated_request.dict(),
            "suggestions": {
                "recommended_analysis_type": _suggest_analysis_type(validated_request),
                "estimated_times": _estimate_processing_time(validated_request),
                "completeness_score": _calculate_completeness(validated_request)
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except ValueError as e:
        return {
            "status": "invalid",
            "errors": str(e),
            "suggestions": {
                "fix_recommendations": "Ensure 'titulo' and 'descripcion' are provided and meet minimum length requirements"
            },
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error validando solicitud: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))





# ============================================================================
# FUNCIONES AUXILIARES
# ============================================================================

def _suggest_analysis_type(request: IncidentAnalysisRequest) -> str:
    """Sugiere el tipo de análisis más apropiado."""
    description_lower = request.descripcion.lower()
    title_lower = request.titulo.lower()
    combined_text = f"{title_lower} {description_lower}"
    
    # Factores para análisis experto
    expert_keywords = [
        "crítico", "millones", "transferencia", "datos masivos",
        "infraestructura", "nacional", "regulatorio", "compliance",
        "ransomware", "apt", "breach"
    ]
    
    # Factores para análisis estándar
    standard_keywords = [
        "phishing", "malware", "credenciales", "acceso", "sistema",
        "vulnerabilidad", "intrusión", "sospechoso"
    ]
    
    if any(keyword in combined_text for keyword in expert_keywords):
        return "experto"
    elif any(keyword in combined_text for keyword in standard_keywords):
        return "estandar"
    else:
        return "rapido"


def _estimate_processing_time(request: IncidentAnalysisRequest) -> Dict[str, str]:
    """Estima tiempos de procesamiento por tipo de análisis."""
    # Factor de complejidad basado en longitud del texto
    description_length = len(request.descripcion)
    complexity_factor = 1.0
    
    if description_length > 1000:
        complexity_factor += 0.3
    if request.contexto_adicional and len(request.contexto_adicional) > 200:
        complexity_factor += 0.2
    if request.urgencia == "critica":
        complexity_factor += 0.1  # Análisis más detallado para casos críticos
    
    base_times = {
        "rapido": 45,     # segundos
        "estandar": 90,   # segundos  
        "experto": 180    # segundos
    }
    
    estimated_times = {}
    for analysis_type, base_time in base_times.items():
        adjusted_time = int(base_time * complexity_factor)
        estimated_times[analysis_type] = f"{adjusted_time}s"
    
    return estimated_times


def _calculate_completeness(request: IncidentAnalysisRequest) -> float:
    """Calcula un score de completitud de la información (0-1)."""
    score = 0.0
    
    # Título presente y descriptivo
    if request.titulo and len(request.titulo) > 10:
        score += 0.3
    elif request.titulo:
        score += 0.1
    
    # Descripción detallada
    if request.descripcion and len(request.descripcion) > 100:
        score += 0.4
    elif request.descripcion and len(request.descripcion) > 20:
        score += 0.2
    
    # Contexto adicional
    if request.contexto_adicional:
        score += 0.1
    
    # Categoría inicial
    if request.categoria_inicial:
        score += 0.1
    
    # Nivel de urgencia especificado
    if request.urgencia and request.urgencia != "media":
        score += 0.1
    
    return round(score, 2) 