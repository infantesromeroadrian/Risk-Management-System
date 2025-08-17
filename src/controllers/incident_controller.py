"""
Risk-Guardian Controller - Versión Limpia
Controller minimalista sin duplicaciones, delega estadísticas al sistema RAG.
"""
from typing import Dict, Any, Optional
from fastapi import HTTPException, BackgroundTasks
from datetime import datetime

from src.models.models import (
    IncidentAnalysisRequest,
    IncidentAnalysisResponse,
    LangChainAnalysisConfig
)
from src.services.langchain_security_analyzer import LangChainSecurityAnalyzer
from src.services.data_service import DataService
from src.services.rag import get_rag_stats, get_rag_health
from src.utils.logger import setup_logger
from src.utils.validators import validate_incident_data

logger = setup_logger(__name__)


class IncidentController:
    """
    Controller simplificado para análisis de incidentes.
    
    Características:
    - Sistema RAG + LangChain + GPT-4.1
    - Sin duplicaciones: delega estadísticas al sistema RAG
    - Sin cache redundante: usa singleton RAG
    - Configuraciones simples y claras
    """

    def __init__(self):
        """Inicializa el controller."""
        # Solo services esenciales
        self.data_service = DataService()
        
        # Configuraciones LangChain simplificadas
        self.analysis_configs = {
            "rapido": LangChainAnalysisConfig(
                modelo_principal="gpt-3.5-turbo",
                modelo_fallback="gpt-3.5-turbo",
                temperatura=0.3,
                max_tokens=1000,
                nivel_detalle="basico",
                usar_streaming=False
            ),
            "estandar": LangChainAnalysisConfig(
                modelo_principal="gpt-4.1-turbo",
                modelo_fallback="gpt-3.5-turbo",
                temperatura=0.3,
                max_tokens=2000,
                nivel_detalle="detallado",
                usar_streaming=True
            ),
            "experto": LangChainAnalysisConfig(
                modelo_principal="gpt-4.1-turbo",
                modelo_fallback="gpt-4.1-turbo",
                temperatura=0.2,
                max_tokens=3000,
                nivel_detalle="experto",
                usar_streaming=True,
                incluir_marcos_referencia=True,
                validar_con_cti=True
            )
        }
        
        logger.info("Incident Controller limpio inicializado")

    # ============================================================================
    # ANÁLISIS PRINCIPAL
    # ============================================================================

    async def analyze_incident(
        self,
        incident_data: Dict[str, Any],
        analysis_type: str = "estandar",
        background_tasks: Optional[BackgroundTasks] = None
    ) -> Dict[str, Any]:
        """
        Analiza un incidente usando LangChain + RAG + GPT-4.1.
        
        Args:
            incident_data: Datos del incidente
            analysis_type: Tipo de análisis (rapido/estandar/experto)
            background_tasks: Tareas en segundo plano (opcional)
            
        Returns:
            dict: Resultado del análisis estructurado
        """
        try:
            # Validar datos
            validation_errors = validate_incident_data(incident_data)
            if validation_errors:
                raise HTTPException(
                    status_code=400,
                    detail={"errors": validation_errors}
                )
            
            # Crear request
            request = IncidentAnalysisRequest(
                titulo=incident_data.get("titulo", ""),
                descripcion=incident_data.get("descripcion", ""),
                categoria_inicial=incident_data.get("categoria_inicial"),
                urgencia=incident_data.get("urgencia", "media"),
                contexto_adicional=incident_data.get("contexto_adicional")
            )
            
            # Obtener configuración y crear analizador
            config = self.analysis_configs.get(analysis_type, self.analysis_configs["estandar"])
            analyzer = LangChainSecurityAnalyzer(config)
            
            # Ejecutar análisis
            logger.info(f"Iniciando análisis {analysis_type}: {request.titulo}")
            start_time = datetime.utcnow()
            
            analysis_response = await analyzer.analyze_incident(request)
            
            processing_time = (datetime.utcnow() - start_time).total_seconds()
            logger.info(f"Análisis completado en {processing_time:.2f}s - ID: {analysis_response.id_analisis}")
            
            return {
                "status": "success",
                "data": analysis_response.data,  # Solo los datos, sin anidación
                "processing_time": processing_time,
                "analysis_type": analysis_type,
                "timestamp": datetime.utcnow().isoformat(),
                "id_analisis": analysis_response.id_analisis,
                "modelo_utilizado": analysis_response.modelo_utilizado
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error en análisis: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"Error interno en análisis: {str(e)}"
            )

    # ============================================================================
    # EJEMPLOS Y CONFIGURACIÓN
    # ============================================================================

    async def get_incident_examples(self) -> Dict[str, Any]:
        """
        Obtiene ejemplos de incidentes desde el data service.
        
        Returns:
            dict: Ejemplos estructurados por categoría
        """
        try:
            examples = self.data_service.load_incident_examples()
            if not examples:
                raise HTTPException(
                    status_code=404,
                    detail="No incident examples found"
                )
            
            return {
                "status": "success",
                "data": examples,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error cargando ejemplos: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail="Error retrieving incident examples"
            )

    async def get_analysis_types(self) -> Dict[str, Any]:
        """
        Obtiene tipos de análisis disponibles con configuraciones.
        
        Returns:
            dict: Tipos de análisis y sus características
        """
        try:
            types_info = {}
            for config_name, config in self.analysis_configs.items():
                types_info[config_name] = {
                    "model": config.modelo_principal,
                    "fallback": config.modelo_fallback,
                    "detail_level": config.nivel_detalle,
                    "streaming": config.usar_streaming,
                    "max_tokens": config.max_tokens
                }
            
            return {
                "status": "success",
                "available_types": types_info,
                "default_type": "estandar",
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error obteniendo tipos de análisis: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail="Error retrieving analysis types"
            )

    # ============================================================================
    # ESTADÍSTICAS (Delegadas al sistema RAG)
    # ============================================================================

    async def get_system_stats(self) -> Dict[str, Any]:
        """
        Obtiene estadísticas del sistema completo.
        Delega al sistema RAG para evitar duplicaciones.
        
        Returns:
            dict: Estadísticas consolidadas
        """
        try:
            # Obtener estadísticas RAG
            rag_stats = await get_rag_stats()
            rag_health = await get_rag_health()
            
            return {
                "status": "success",
                "controller": {
                    "available_analysis_types": list(self.analysis_configs.keys()),
                    "framework": "langchain-rag",
                    "version": "2.1.0-clean"
                },
                "rag_system": rag_stats,
                "system_health": rag_health,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error obteniendo estadísticas: {str(e)}")
            return {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }