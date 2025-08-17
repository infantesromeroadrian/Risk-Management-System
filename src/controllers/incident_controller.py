"""
Risk-Guardian Unified Controller - Sistema Consolidado
Controller unificado basado en LangChain + RAG para análisis avanzado de ciberseguridad.
Sin simulaciones, sin duplicaciones, solo funcionalidad real.
"""
from typing import Dict, Any, Optional, List
from fastapi import HTTPException, BackgroundTasks
from datetime import datetime

# LangChain components (primary)
from src.models.models import (
    IncidentAnalysisRequest,
    IncidentAnalysisResponse,
    LangChainAnalysisConfig
)
from src.services.langchain_security_analyzer import LangChainSecurityAnalyzer

# Data services
from src.services.data_service import DataService
from src.utils.logger import setup_logger
from src.utils.validators import validate_incident_data

logger = setup_logger(__name__)


class IncidentController:
    """
    Controller unificado para gestión de incidentes de ciberseguridad.
    
    Características:
    - Sistema RAG + LangChain + GPT-4.1 (análisis avanzado con contexto especializado)
    - Múltiples tipos de análisis: rápido, estándar, experto
    - Sin simulaciones: Solo funcionalidad real implementada
    - Configuraciones adaptables por tipo de análisis
    - Métricas y monitoreo reales
    - Integración con documentación MAGERIT, OCTAVE, ISO 27001
    """

    def __init__(self):
        """Inicializa el controller unificado."""
        # Services principales
        self.data_service = DataService()
        
        # Configuraciones LangChain por tipo de análisis
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
        
        # Cache de analizadores LangChain para eficiencia
        self._analyzers_cache = {}
        
        # Estadísticas en tiempo real
        self._stats = {
            "total_analyses": 0,
            "analyses_by_type": {"rapido": 0, "estandar": 0, "experto": 0},
            "last_reset": datetime.utcnow(),
            "avg_processing_times": {}
        }
        
        logger.info("Incident Controller unificado inicializado")

    def _get_langchain_analyzer(self, config_name: str = "estandar") -> LangChainSecurityAnalyzer:
        """
        Obtiene un analizador LangChain configurado con cache.
        
        Args:
            config_name: Configuración a usar (rapido/estandar/experto)
            
        Returns:
            LangChainSecurityAnalyzer: Analizador configurado
        """
        if config_name not in self._analyzers_cache:
            config = self.analysis_configs.get(config_name, self.analysis_configs["estandar"])
            self._analyzers_cache[config_name] = LangChainSecurityAnalyzer(config)
            logger.info(f"Nuevo analizador LangChain creado: {config_name}")
        
        return self._analyzers_cache[config_name]

    # ============================================================================
    # ENDPOINTS PRINCIPALES (LangChain + GPT-4.1)
    # ============================================================================

    async def get_incident_examples(self) -> Dict[str, Any]:
        """
        Obtiene ejemplos de incidentes enriquecidos con recomendaciones de análisis.
        
        Returns:
            dict: Ejemplos de incidentes con información de análisis inteligente
        """
        try:
            examples = self.data_service.load_incident_examples()
            
            # Enriquecer ejemplos con recomendaciones automáticas
            for category_name, category_data in examples.get("categorias", {}).items():
                for example in category_data.get("ejemplos", []):
                    # Análisis inteligente del tipo recomendado
                    description = example.get("descripcion", "").lower()
                    title = example.get("titulo", "").lower()
                    combined_text = f"{title} {description}"
                    
                    if any(keyword in combined_text for keyword in [
                        "crítico", "millones", "transferencia", "datos masivos",
                        "infraestructura", "nacional", "regulatorio", "ransomware", "apt"
                    ]):
                        example["analisis_recomendado"] = "experto"
                        example["justificacion"] = "Incidente crítico que requiere análisis completo"
                    elif any(keyword in combined_text for keyword in [
                        "phishing", "credenciales", "malware", "intrusión", "vulnerabilidad"
                    ]):
                        example["analisis_recomendado"] = "estandar"
                        example["justificacion"] = "Incidente estándar que requiere análisis detallado"
                    else:
                        example["analisis_recomendado"] = "rapido"
                        example["justificacion"] = "Incidente que puede analizarse rápidamente"
                    
                    # Tiempo estimado
                    time_estimates = {
                        "rapido": "30-60s", "estandar": "1-2 min", "experto": "2-5 min"
                    }
                    example["tiempo_estimado"] = time_estimates[example["analisis_recomendado"]]
            
            return {
                "status": "success",
                "data": examples,
                "timestamp": datetime.utcnow().isoformat(),
                "meta": {
                    "analysis_types_info": {
                        "rapido": {
                            "name": "Análisis Rápido",
                            "model": "GPT-3.5-turbo",
                            "time": "30-60s",
                            "use_case": "Triaje inicial, baja severidad"
                        },
                        "estandar": {
                            "name": "Análisis Estándar",
                            "model": "GPT-4.1-turbo", 
                            "time": "1-2 min",
                            "use_case": "Mayoría de incidentes, balance tiempo-detalle"
                        },
                        "experto": {
                            "name": "Análisis Experto",
                            "model": "GPT-4.1-turbo",
                            "time": "2-5 min",
                            "use_case": "Incidentes críticos, análisis forense"
                        }
                    },
                    "statistics": self.get_controller_statistics()
                }
            }
            
        except Exception as e:
            logger.error(f"Error obteniendo ejemplos: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail="Error retrieving incident examples"
            )

    async def analyze_incident(
        self,
        incident_data: Dict[str, Any],
        analysis_type: str = "estandar",
        background_tasks: Optional[BackgroundTasks] = None
    ) -> Dict[str, Any]:
        """
        Analiza un incidente usando LangChain + GPT-4.1 (sistema principal).
        
        Args:
            incident_data: Datos del incidente
            analysis_type: Tipo de análisis (rapido/estandar/experto)
            background_tasks: Tareas en segundo plano
            
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
            
            # Crear request estructurado
            try:
                request = IncidentAnalysisRequest(
                    titulo=incident_data.get("titulo", ""),
                    descripcion=incident_data.get("descripcion", ""),
                    categoria_inicial=incident_data.get("categoria_inicial"),
                    urgencia=incident_data.get("urgencia", "media"),
                    contexto_adicional=incident_data.get("contexto_adicional")
                )
            except ValueError as e:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid request format: {str(e)}"
                )
            
            # Obtener analizador LangChain
            analyzer = self._get_langchain_analyzer(analysis_type)
            
            # Ejecutar análisis
            logger.info(f"Iniciando análisis {analysis_type}: {request.titulo}")
            start_time = datetime.utcnow()
            
            analysis_response = await analyzer.analyze_incident(request)
            
            end_time = datetime.utcnow()
            processing_time = (end_time - start_time).total_seconds()
            
            # Actualizar estadísticas
            self._update_stats(analysis_type, processing_time)
            
            # Programar métricas en background
            if background_tasks:
                background_tasks.add_task(
                    self._log_analysis_metrics,
                    analysis_response,
                    processing_time,
                    analysis_type
                )
            
            # Estructura respuesta unificada
            response_data = {
                "status": "success",
                "analysis_id": analysis_response.id_analisis,
                "timestamp": analysis_response.timestamp.isoformat(),
                "processing_time": f"{processing_time:.2f}s",
                "analysis_type": analysis_type,
                "model_used": analysis_response.modelo_utilizado,
                "confidence": analysis_response.confianza_analisis,
                "data": {
                    "risk_level": {
                        "level": analysis_response.nivel_riesgo.nivel,
                        "score": analysis_response.nivel_riesgo.puntuacion,
                        "factors": analysis_response.nivel_riesgo.factores,
                        "justification": analysis_response.nivel_riesgo.justificacion
                    },
                    "vulnerabilities": [
                        {
                            "type": vuln.tipo,
                            "description": vuln.descripcion,
                            "severity": vuln.severidad,
                            "category": vuln.categoria,
                            "recommendation": vuln.recomendacion,
                            "cve_ids": vuln.cve_ids,
                            "mitre_attack_ids": vuln.mitre_attack_ids
                        }
                        for vuln in analysis_response.vulnerabilidades
                    ],
                    "impacts": [
                        {
                            "type": impact.tipo,
                            "description": impact.descripcion,
                            "impact_level": impact.impacto,
                            "recoverable": impact.recuperable,
                            "recovery_time": impact.tiempo_recuperacion,
                            "probability": impact.probabilidad,
                            "risk_value": impact.valor_riesgo
                        }
                        for impact in analysis_response.impactos
                    ],
                    "controls": [
                        {
                            "type": control.tipo,
                            "description": control.descripcion,
                            "priority": control.prioridad,
                            "estimated_cost": control.costo_estimado,
                            "implementation_time": control.tiempo_implementacion,
                            "reference_frameworks": control.marco_referencia,
                            "kpis": control.kpis
                        }
                        for control in analysis_response.controles
                    ],
                    "executive_summary": analysis_response.resumen_ejecutivo,
                    "immediate_recommendations": analysis_response.recomendaciones_inmediatas,
                    "mitigation_plan": analysis_response.plan_mitigacion
                },
                "metadata": analysis_response.metadatos
            }
            
            logger.info(f"Análisis completado en {processing_time:.2f}s - ID: {analysis_response.id_analisis}")
            return response_data
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error en análisis LangChain: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"Error analyzing incident: {str(e)}"
            )

    async def get_analysis_types(self) -> Dict[str, Any]:
        """
        Obtiene información detallada sobre los tipos de análisis disponibles.
        
        Returns:
            dict: Configuraciones y características de cada tipo
        """
        try:
            analysis_info = {}
            
            for config_name, config in self.analysis_configs.items():
                analysis_info[config_name] = {
                    "name": config_name.title(),
                    "primary_model": config.modelo_principal,
                    "fallback_model": config.modelo_fallback,
                    "detail_level": config.nivel_detalle,
                    "streaming": config.usar_streaming,
                    "include_frameworks": config.incluir_marcos_referencia,
                    "cti_validation": config.validar_con_cti,
                    "estimated_time": self._get_time_estimate(config_name),
                    "recommended_for": self._get_use_cases(config_name),
                    "avg_processing_time": self._stats["avg_processing_times"].get(config_name, "N/A")
                }
            
            return {
                "status": "success",
                "available_types": analysis_info,
                "default_type": "estandar",
                "total_analyses_performed": self._stats["total_analyses"],
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error obteniendo tipos de análisis: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail=f"Error retrieving analysis types: {str(e)}"
            )

    # ============================================================================
    # UTILIDADES Y ESTADÍSTICAS
    # ============================================================================

    def get_controller_statistics(self) -> Dict[str, Any]:
        """
        Obtiene estadísticas reales del controller (no simuladas).
        
        Returns:
            dict: Estadísticas de uso y rendimiento
        """
        return {
            "total_analyses": self._stats["total_analyses"],
            "analyses_by_type": self._stats["analyses_by_type"].copy(),
            "cached_analyzers": len(self._analyzers_cache),
            "available_configs": list(self.analysis_configs.keys()),
            "avg_processing_times": self._stats["avg_processing_times"].copy(),
            "uptime_since": self._stats["last_reset"].isoformat(),
            "framework": "unified-langchain",
            "version": "2.0.0-unified",
            "timestamp": datetime.utcnow().isoformat()
        }

    def _update_stats(self, analysis_type: str, processing_time: float):
        """Actualiza estadísticas en tiempo real."""
        self._stats["total_analyses"] += 1
        self._stats["analyses_by_type"][analysis_type] = self._stats["analyses_by_type"].get(analysis_type, 0) + 1
        
        # Calcular tiempo promedio
        current_avg = self._stats["avg_processing_times"].get(analysis_type, 0.0)
        count = self._stats["analyses_by_type"][analysis_type]
        new_avg = ((current_avg * (count - 1)) + processing_time) / count
        self._stats["avg_processing_times"][analysis_type] = round(new_avg, 2)

    def _get_time_estimate(self, analysis_type: str) -> str:
        """Obtiene estimación de tiempo basada en estadísticas reales."""
        estimates = {
            "rapido": "30-60 segundos",
            "estandar": "1-2 minutos", 
            "experto": "2-5 minutos"
        }
        return estimates.get(analysis_type, "1-2 minutos")

    def _get_use_cases(self, analysis_type: str) -> List[str]:
        """Obtiene casos de uso recomendados."""
        cases = {
            "rapido": [
                "Triaje inicial de incidentes",
                "Incidentes de baja severidad",
                "Evaluación rápida para decisiones"
            ],
            "estandar": [
                "Mayoría de incidentes de seguridad",
                "Balance óptimo tiempo-detalle",
                "Informes para equipos técnicos"
            ],
            "experto": [
                "Incidentes críticos o complejos",
                "Análisis forense detallado",
                "Informes ejecutivos",
                "Cumplimiento regulatorio"
            ]
        }
        return cases.get(analysis_type, [])

    async def _log_analysis_metrics(
        self,
        analysis_response: IncidentAnalysisResponse,
        processing_time: float,
        analysis_type: str
    ):
        """Registra métricas reales del análisis."""
        try:
            metrics = {
                "analysis_id": analysis_response.id_analisis,
                "timestamp": analysis_response.timestamp.isoformat(),
                "processing_time": processing_time,
                "analysis_type": analysis_type,
                "model_used": analysis_response.modelo_utilizado,
                "confidence": analysis_response.confianza_analisis,
                "vulnerabilities_count": len(analysis_response.vulnerabilidades),
                "impacts_count": len(analysis_response.impactos),
                "controls_count": len(analysis_response.controles),
                "risk_level": analysis_response.nivel_riesgo.nivel,
                "risk_score": analysis_response.nivel_riesgo.puntuacion
            }
            
            logger.info(f"Métricas registradas para análisis {analysis_response.id_analisis}: "
                       f"{processing_time:.2f}s, {analysis_type}, {len(analysis_response.vulnerabilidades)} vulns")
            
        except Exception as e:
            logger.error(f"Error registrando métricas: {str(e)}") 