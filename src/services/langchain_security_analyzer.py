"""
LangChain Security Analyzer para Risk-Guardian
Analizador avanzado de incidentes de ciberseguridad usando LangChain + GPT-4.
"""
import json
import uuid
from datetime import datetime
from typing import Dict, Any, Optional, List

from langchain_openai import ChatOpenAI
from langchain_core.output_parsers import PydanticOutputParser, JsonOutputParser
from langchain_core.runnables import RunnablePassthrough, RunnableBranch, RunnableLambda
from langchain_core.exceptions import LangChainException
from langchain.callbacks.streaming_stdout import StreamingStdOutCallbackHandler
from langchain.callbacks.manager import CallbackManager

from src.models.models import (
    IncidentAnalysisRequest,
    IncidentAnalysisResponse,
    LangChainAnalysisConfig,
    Vulnerability,
    Impact,
    Control,
    RiskLevel,
    SeverityLevel
)
from src.services.rag import get_rag_service
from src.prompts.security_analysis_prompts import (
    create_security_analysis_prompt,
    create_risk_assessment_prompt,
    create_executive_summary_prompt,
    create_mitigation_plan_prompt,
    get_prompt_by_incident_type
)
from src.utils.logger import setup_logger
from src.utils.config import config

logger = setup_logger(__name__)


class LangChainSecurityAnalyzer:
    """
    Analizador de seguridad avanzado usando LangChain y GPT-4.
    
    Características:
    - Análisis multi-modelo con fallbacks
    - Streaming de respuestas en tiempo real
    - Validación estructurada con Pydantic
    - Análisis especializado por tipo de incidente
    - Integración con marcos de seguridad (MAGERIT, OCTAVE, etc.)
    """

    def __init__(self, config: Optional[LangChainAnalysisConfig] = None):
        """
        Inicializa el analizador de seguridad con LangChain.
        
        Args:
            config: Configuración específica para el análisis
        """
        self.config = config or LangChainAnalysisConfig()
        self._setup_models()
        self._setup_parsers()
        self._setup_chains()
        logger.info("LangChain Security Analyzer inicializado correctamente")

    def _setup_models(self):
        """Configura los modelos de OpenAI con LangChain."""
        try:
            # Modelo principal (GPT-4)
            self.primary_model = ChatOpenAI(
                model=self.config.modelo_principal,
                temperature=self.config.temperatura,
                max_tokens=self.config.max_tokens,
                openai_api_key=config.get("openai_api_key"),
                callbacks=[StreamingStdOutCallbackHandler()] if self.config.usar_streaming else None,
                streaming=self.config.usar_streaming
            )
            
            # Modelo de fallback (GPT-3.5-turbo)
            self.fallback_model = ChatOpenAI(
                model=self.config.modelo_fallback,
                temperature=self.config.temperatura,
                max_tokens=self.config.max_tokens,
                openai_api_key=config.get("openai_api_key"),
                streaming=False  # Fallback no necesita streaming
            )
            
            # Modelo con fallback automático
            self.model_with_fallback = self.primary_model.with_fallbacks([self.fallback_model])
            
            logger.info(f"Modelos configurados: {self.config.modelo_principal} → {self.config.modelo_fallback}")
            
        except Exception as e:
            logger.error(f"Error configurando modelos: {str(e)}")
            raise

    def _setup_parsers(self):
        """Configura los parsers de output estructurado."""
        # Parser para análisis completo
        self.analysis_parser = PydanticOutputParser(pydantic_object=IncidentAnalysisResponse)
        
        # Parser para componentes individuales
        self.vulnerability_parser = PydanticOutputParser(pydantic_object=Vulnerability)
        self.impact_parser = PydanticOutputParser(pydantic_object=Impact)
        self.control_parser = PydanticOutputParser(pydantic_object=Control)
        self.risk_parser = PydanticOutputParser(pydantic_object=RiskLevel)
        
        # Parser JSON genérico para casos de fallback
        self.json_parser = JsonOutputParser()
        
        logger.info("Output parsers configurados correctamente")

    def _setup_chains(self):
        """Configura las cadenas de procesamiento con LangChain."""
        try:
            # Chain principal de análisis
            self.analysis_prompt = create_security_analysis_prompt()
            self.analysis_chain = (
                RunnablePassthrough.assign(
                    contexto_adicional=lambda x: self._prepare_context(x)
                )
                | self.analysis_prompt
                | self.model_with_fallback
                | self._create_robust_parser()
            )
            
            # Chain para evaluación de riesgo
            self.risk_prompt = create_risk_assessment_prompt()
            self.risk_chain = (
                self.risk_prompt
                | self.model_with_fallback
                | self.json_parser
            )
            
            # Chain para resumen ejecutivo
            self.executive_prompt = create_executive_summary_prompt()
            self.executive_chain = (
                self.executive_prompt
                | self.model_with_fallback
                | RunnableLambda(lambda x: x.content)
            )
            
            # Chain para plan de mitigación
            self.mitigation_prompt = create_mitigation_plan_prompt()
            self.mitigation_chain = (
                self.mitigation_prompt
                | self.model_with_fallback
                | RunnableLambda(lambda x: x.content)
            )
            
            logger.info("Chains de LangChain configuradas correctamente")
            
        except Exception as e:
            logger.error(f"Error configurando chains: {str(e)}")
            raise

    def _create_robust_parser(self):
        """
        Crea un parser robusto que maneja diferentes formatos de respuesta.
        """
        def parse_with_fallback(response):
            try:
                # Intentar parsing directo como JSON
                if hasattr(response, 'content'):
                    content = response.content
                else:
                    content = str(response)
                
                # Limpiar el contenido si contiene markdown
                if content.startswith('```json'):
                    content = content.replace('```json', '').replace('```', '').strip()
                
                # Buscar el JSON válido en el contenido (manejar texto adicional)
                parsed_data = self._extract_json_from_content(content)
                
                # Validar estructura mínima
                if not all(key in parsed_data for key in ['vulnerabilidades', 'impactos', 'controles']):
                    raise ValueError("Estructura JSON incompleta")
                
                return parsed_data
                
            except (json.JSONDecodeError, ValueError) as e:
                logger.warning(f"Error parsing JSON: {str(e)}. Usando fallback.")
                return self._create_fallback_response()
        
        return RunnableLambda(parse_with_fallback)

    def _extract_json_from_content(self, content: str) -> Dict[str, Any]:
        """
        Extrae JSON válido del contenido, manejando texto adicional.
        
        Args:
            content: Texto que puede contener JSON + texto adicional
            
        Returns:
            Dict: Datos JSON parseados
            
        Raises:
            json.JSONDecodeError: Si no se puede parsear JSON válido
        """
        try:
            # Primero intentar parsing directo
            return json.loads(content)
        except json.JSONDecodeError:
            # Si falla, buscar el primer objeto JSON válido
            import re
            
            # Buscar patrones que indiquen el inicio y fin de JSON
            json_pattern = r'\{.*?\}\s*(?=\n\n|\n[A-Z]|\n\*\*|$)'
            matches = re.findall(json_pattern, content, re.DOTALL)
            
            if matches:
                # Intentar con la coincidencia más larga (probablemente el JSON completo)
                for match in sorted(matches, key=len, reverse=True):
                    try:
                        return json.loads(match.strip())
                    except json.JSONDecodeError:
                        continue
            
            # Si no encuentra patrones, buscar entre llaves balanceadas
            start_idx = content.find('{')
            if start_idx != -1:
                brace_count = 0
                for i, char in enumerate(content[start_idx:], start_idx):
                    if char == '{':
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            json_text = content[start_idx:i+1]
                            return json.loads(json_text)
            
            # Si todo falla, lanzar el error original
            raise json.JSONDecodeError("No se pudo extraer JSON válido", content, 0)

    def _create_fallback_response(self) -> Dict[str, Any]:
        """
        Crea una respuesta de fallback cuando el parsing falla.
        
        Returns:
            Dict: Respuesta estructurada de fallback
        """
        return {
            "vulnerabilidades": [
                {
                    "tipo": "procesos",
                    "descripcion": "Análisis automatizado no pudo completarse. Revisión manual requerida.",
                    "severidad": "media",
                    "categoria": "análisis de incidentes",
                    "recomendacion": "Realizar análisis manual detallado del incidente"
                }
            ],
            "impactos": [
                {
                    "tipo": "operacional",
                    "descripcion": "Potencial impacto desconocido por limitaciones en el análisis automatizado",
                    "impacto": "media",
                    "recuperable": True,
                    "tiempo_recuperacion": "a determinar"
                }
            ],
            "controles": [
                {
                    "tipo": "correctivo",
                    "descripcion": "Realizar análisis manual exhaustivo del incidente",
                    "prioridad": "alta",
                    "costo_estimado": "bajo",
                    "tiempo_implementacion": "inmediato"
                }
            ]
        }

    def _prepare_context(self, input_data: Dict[str, Any]) -> str:
        """
        Prepara contexto adicional para el análisis.
        
        Args:
            input_data: Datos de entrada del incidente
            
        Returns:
            str: Contexto adicional formatado
        """
        context_parts = []
        
        if input_data.get("urgencia"):
            context_parts.append(f"**Urgencia:** {input_data['urgencia']}")
        
        if input_data.get("contexto_adicional"):
            context_parts.append(f"**Contexto adicional:** {input_data['contexto_adicional']}")
        
        if input_data.get("categoria_inicial"):
            context_parts.append(f"**Categoría inicial sospechada:** {input_data['categoria_inicial']}")
        
        # Agregar información de configuración de análisis
        context_parts.append(f"**Nivel de detalle requerido:** {self.config.nivel_detalle}")
        
        if self.config.incluir_marcos_referencia:
            context_parts.append("**Marcos de referencia:** Incluir referencias a ISO 27001, NIST, CIS Controls, MAGERIT")
        
        return "\n".join(context_parts) if context_parts else ""

    def _calculate_risk_level(self, vulnerabilities: List[Dict], impacts: List[Dict]) -> Dict[str, Any]:
        """
        Calcula el nivel de riesgo basado en vulnerabilidades e impactos.
        
        Args:
            vulnerabilities: Lista de vulnerabilidades identificadas
            impacts: Lista de impactos potenciales
            
        Returns:
            Dict: Información del nivel de riesgo
        """
        try:
            # Lógica de cálculo de riesgo mejorada
            severity_weights = {
                "baja": 1,
                "media": 2, 
                "alta": 3,
                "critica": 4
            }
            
            # Calcular puntuación de vulnerabilidades
            vuln_score = sum(severity_weights.get(v.get("severidad", "media"), 2) for v in vulnerabilities)
            
            # Calcular puntuación de impactos
            impact_score = sum(severity_weights.get(i.get("impacto", "media"), 2) for i in impacts)
            
            # Puntuación total
            total_score = (vuln_score + impact_score) / 2
            
            # Determinar nivel de riesgo
            if total_score >= 3.5:
                risk_level = "critica"
            elif total_score >= 2.5:
                risk_level = "alta"
            elif total_score >= 1.5:
                risk_level = "media"
            else:
                risk_level = "baja"
            
            factors = [
                f"Vulnerabilidades críticas: {len([v for v in vulnerabilities if v.get('severidad') == 'critica'])}",
                f"Impactos críticos: {len([i for i in impacts if i.get('impacto') == 'critica'])}",
                f"Puntuación total: {total_score:.2f}"
            ]
            
            return {
                "nivel": risk_level,
                "puntuacion": total_score * 25,  # Escalar a 0-100
                "factores": factors,
                "justificacion": f"Nivel de riesgo {risk_level} basado en análisis cuantitativo de vulnerabilidades e impactos"
            }
            
        except Exception as e:
            logger.error(f"Error calculando nivel de riesgo: {str(e)}")
            return {
                "nivel": "media",
                "puntuacion": 50.0,
                "factores": ["Error en cálculo automático"],
                "justificacion": "Nivel de riesgo por defecto debido a error en cálculo"
            }

    async def analyze_incident(self, request: IncidentAnalysisRequest) -> IncidentAnalysisResponse:
        """
        Analiza un incidente de ciberseguridad usando LangChain.
        
        Args:
            request: Solicitud de análisis de incidente
            
        Returns:
            IncidentAnalysisResponse: Respuesta estructurada del análisis
        """
        analysis_id = str(uuid.uuid4())
        
        try:
            logger.info(f"Iniciando análisis de incidente {analysis_id}: {request.titulo}")
            
            # Buscar contexto relevante usando RAG
            rag_context = await self._get_rag_context(request)
            
            # Preparar datos de entrada para la chain (con contexto RAG)
            input_data = {
                "titulo": request.titulo,
                "descripcion": request.descripcion,
                "urgencia": request.urgencia,
                "contexto_adicional": request.contexto_adicional or "",
                "categoria_inicial": request.categoria_inicial or "",
                "rag_context": rag_context  # Nuevo: contexto de documentación
            }
            
            # Ejecutar análisis principal
            analysis_result = await self.analysis_chain.ainvoke(input_data)
            
            # Calcular nivel de riesgo
            risk_level = self._calculate_risk_level(
                analysis_result["vulnerabilidades"],
                analysis_result["impactos"]
            )
            
            # Generar resumen ejecutivo
            executive_summary = await self._generate_executive_summary(
                request.titulo,
                risk_level,
                analysis_result
            )
            
            # Extraer recomendaciones inmediatas
            immediate_recommendations = self._extract_immediate_recommendations(
                analysis_result["controles"]
            )
            
            # Construir respuesta estructurada
            response = IncidentAnalysisResponse(
                status="success",  # Campo obligatorio
                data={  # Campo obligatorio
                    "vulnerabilidades": [v for v in analysis_result["vulnerabilidades"]],
                    "impactos": [i for i in analysis_result["impactos"]],
                    "controles": [c for c in analysis_result["controles"]]
                },
                id_analisis=analysis_id,
                timestamp=datetime.utcnow(),
                modelo_utilizado=f"{self.config.modelo_principal} (fallback: {self.config.modelo_fallback})",
                nivel_riesgo=RiskLevel(**risk_level),
                vulnerabilidades=[Vulnerability(**v) for v in analysis_result["vulnerabilidades"]],
                impactos=[Impact(**i) for i in analysis_result["impactos"]],
                controles=[Control(**c) for c in analysis_result["controles"]],
                resumen_ejecutivo=executive_summary,
                recomendaciones_inmediatas=immediate_recommendations,
                confianza_analisis=self._calculate_confidence(analysis_result),
                metadatos={
                    "model_config": self.config.dict(),
                    "analysis_version": "langchain-v1.0",
                    "processing_time": "calculated_later"
                }
            )
            
            logger.info(f"Análisis completado exitosamente para {analysis_id}")
            return response
            
        except Exception as e:
            logger.error(f"Error en análisis de incidente {analysis_id}: {str(e)}")
            return self._create_error_response(analysis_id, str(e))

    async def _generate_executive_summary(
        self, 
        titulo: str, 
        risk_level: Dict[str, Any], 
        analysis_result: Dict[str, Any]
    ) -> str:
        """
        Genera un resumen ejecutivo del análisis.
        
        Args:
            titulo: Título del incidente
            risk_level: Nivel de riesgo calculado
            analysis_result: Resultado del análisis
            
        Returns:
            str: Resumen ejecutivo
        """
        try:
            critical_vulns = [v for v in analysis_result["vulnerabilidades"] if v.get("severidad") == "critica"]
            high_impact = [i for i in analysis_result["impactos"] if i.get("impacto") in ["critica", "alta"]]
            priority_controls = [c for c in analysis_result["controles"] if c.get("prioridad") in ["critica", "alta"]]
            
            executive_input = {
                "titulo": titulo,
                "nivel_riesgo": risk_level["nivel"],
                "vulnerabilidades_criticas": len(critical_vulns),
                "impacto_economico": "A determinar según análisis detallado",
                "controles_prioritarios": len(priority_controls)
            }
            
            return await self.executive_chain.ainvoke(executive_input)
            
        except Exception as e:
            logger.error(f"Error generando resumen ejecutivo: {str(e)}")
            return f"Incidente de seguridad '{titulo}' requiere atención inmediata. Nivel de riesgo: {risk_level.get('nivel', 'indeterminado')}."

    def _extract_immediate_recommendations(self, controles: List[Dict[str, Any]]) -> List[str]:
        """
        Extrae recomendaciones que requieren acción inmediata.
        
        Args:
            controles: Lista de controles recomendados
            
        Returns:
            List[str]: Lista de recomendaciones inmediatas
        """
        immediate = []
        
        for control in controles:
            if control.get("prioridad") in ["critica", "alta"]:
                tiempo = control.get("tiempo_implementacion", "")
                if any(keyword in tiempo.lower() for keyword in ["inmediato", "24 horas", "1 día", "urgente"]):
                    immediate.append(control["descripcion"])
        
        # Asegurar que siempre hay al least una recomendación
        if not immediate and controles:
            immediate.append(controles[0]["descripcion"])
        
        return immediate[:5]  # Limitar a 5 recomendaciones inmediatas

    def _calculate_confidence(self, analysis_result: Dict[str, Any]) -> float:
        """
        Calcula el nivel de confianza del análisis.
        
        Args:
            analysis_result: Resultado del análisis
            
        Returns:
            float: Nivel de confianza (0-1)
        """
        try:
            # Factores que influyen en la confianza
            vuln_count = len(analysis_result.get("vulnerabilidades", []))
            impact_count = len(analysis_result.get("impactos", []))
            control_count = len(analysis_result.get("controles", []))
            
            # Base de confianza
            base_confidence = 0.7
            
            # Ajustes basados en completitud del análisis
            if vuln_count >= 2 and impact_count >= 2 and control_count >= 3:
                base_confidence += 0.2
            elif vuln_count >= 1 and impact_count >= 1 and control_count >= 2:
                base_confidence += 0.1
            
            # Ajuste por uso del modelo principal
            if self.config.modelo_principal == "gpt-4.1-turbo":
                base_confidence += 0.05
            
            return min(base_confidence, 0.95)  # Cap en 95%
            
        except Exception:
            return 0.7  # Confianza por defecto

    def _create_error_response(self, analysis_id: str, error_message: str) -> IncidentAnalysisResponse:
        """
        Crea una respuesta de error estructurada.
        
        Args:
            analysis_id: ID del análisis
            error_message: Mensaje de error
            
        Returns:
            IncidentAnalysisResponse: Respuesta de error
        """
        return IncidentAnalysisResponse(
            status="error",  # Campo obligatorio
            data={"error": error_message, "vulnerabilidades": [], "impactos": [], "controles": []},  # Campo obligatorio
            id_analisis=analysis_id,
            timestamp=datetime.utcnow(),
            modelo_utilizado="error_handler",
            nivel_riesgo=RiskLevel(
                nivel=SeverityLevel.MEDIA,
                puntuacion=50.0,
                factores=["Error en análisis automatizado"],
                justificacion="Análisis no completado debido a error técnico"
            ),
            vulnerabilidades=[],
            impactos=[],
            controles=[],
            resumen_ejecutivo="Error en el análisis. Se requiere revisión manual.",
            recomendaciones_inmediatas=["Realizar análisis manual del incidente"],
            confianza_analisis=0.0,
            metadatos={"error": error_message}
        )

    async def generate_mitigation_plan(
        self, 
        analysis_response: IncidentAnalysisResponse,
        budget: Optional[str] = None,
        timeline: Optional[str] = None
    ) -> str:
        """
        Genera un plan de mitigación detallado.
        
        Args:
            analysis_response: Respuesta del análisis de incidente
            budget: Presupuesto disponible
            timeline: Timeline objetivo
            
        Returns:
            str: Plan de mitigación detallado
        """
        try:
            mitigation_input = {
                "titulo": "Plan de Mitigación",
                "vulnerabilidades": [v.dict() for v in analysis_response.vulnerabilidades],
                "controles": [c.dict() for c in analysis_response.controles],
                "presupuesto": budget or "A determinar",
                "timeline": timeline or "Según prioridades identificadas"
            }
            
            return await self.mitigation_chain.ainvoke(mitigation_input)
            
        except Exception as e:
            logger.error(f"Error generando plan de mitigación: {str(e)}")
            return "Error generando plan de mitigación. Consultar con especialista en seguridad."

    async def _get_rag_context(self, request: IncidentAnalysisRequest) -> str:
        """
        Obtiene contexto relevante usando RAG para enriquecer el análisis.
        
        Args:
            request: Solicitud de análisis de incidente
            
        Returns:
            str: Contexto formateado de la documentación
        """
        try:
            # Crear query de búsqueda combinando título y descripción
            search_query = f"{request.titulo}. {request.descripcion}"
            if request.categoria_inicial:
                search_query += f". Categoría: {request.categoria_inicial}"
            
            logger.info(f"Buscando contexto RAG para: {search_query[:100]}...")
            
            # Obtener servicio RAG
            rag_service = await get_rag_service()
            
            # Buscar contexto relevante (5 chunks máximo para no sobrecargar el prompt)
            context_chunks = await rag_service.search_relevant_context(
                search_query, 
                max_chunks=5
            )
            
            if not context_chunks:
                logger.warning("No se encontró contexto RAG relevante")
                return ""
            
            # Formatear contexto para el prompt
            formatted_context = rag_service.format_context_for_prompt(context_chunks)
            
            logger.info(f"Contexto RAG obtenido: {len(context_chunks)} chunks relevantes")
            return formatted_context
            
        except Exception as e:
            logger.error(f"Error obteniendo contexto RAG: {str(e)}")
            # Si falla RAG, continuar sin contexto
            return ""

    def get_analysis_statistics(self) -> Dict[str, Any]:
        """
        Obtiene estadísticas del analizador.
        
        Returns:
            Dict: Estadísticas de uso y rendimiento
        """
        return {
            "model_config": self.config.dict(),
            "primary_model": self.config.modelo_principal,
            "fallback_model": self.config.modelo_fallback,
            "streaming_enabled": self.config.usar_streaming,
            "memory_enabled": self.config.usar_memoria,
            "framework": "langchain",
            "version": "1.0.0",
            "rag_enabled": True  # Indicar que RAG está habilitado
        }
