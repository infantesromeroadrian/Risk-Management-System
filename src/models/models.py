"""
Risk-Guardian Unified Models - Sistema Consolidado
Modelos Pydantic unificados para análisis de incidentes de ciberseguridad.
Sin duplicaciones, solo funcionalidad real y completa.
"""
from datetime import datetime
from typing import List, Optional, Dict, Any, Literal
from pydantic import BaseModel, Field
from enum import Enum


# ============================================================================
# ENUMS Y TIPOS BASE
# ============================================================================

class SeverityLevel(str, Enum):
    """Niveles de severidad basados en MAGERIT."""
    BAJA = "baja"
    MEDIA = "media"
    ALTA = "alta"
    CRITICA = "critica"


class VulnerabilityType(str, Enum):
    """Tipos de vulnerabilidades según MAGERIT."""
    PERSONAS = "personas"
    TECNOLOGIA = "tecnologia"
    PROCESOS = "procesos"
    FISICA = "fisica"


class ImpactType(str, Enum):
    """Tipos de impacto organizacional."""
    ECONOMICO = "economico"
    REPUTACIONAL = "reputacional"
    OPERACIONAL = "operacional"
    LEGAL = "legal"
    SEGURIDAD = "seguridad"


class ControlType(str, Enum):
    """Tipos de controles de seguridad."""
    PREVENTIVO = "preventivo"
    DETECTIVO = "detectivo"
    CORRECTIVO = "correctivo"
    DISUASORIO = "disuasorio"
    COMPENSATORIO = "compensatorio"


class Priority(str, Enum):
    """Niveles de prioridad para implementación."""
    BAJA = "baja"
    MEDIA = "media"
    ALTA = "alta"
    CRITICA = "critica"


class CostLevel(str, Enum):
    """Niveles de coste estimado."""
    BAJO = "bajo"
    MEDIO = "medio"
    ALTO = "alto"
    MUY_ALTO = "muy_alto"


class IncidentStatus(str, Enum):
    """Estados de incidentes."""
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    CLOSED = "closed"


# ============================================================================
# MODELOS CORE (Unificados y Completos)
# ============================================================================

class Vulnerability(BaseModel):
    """
    Modelo unificado para vulnerabilidades identificadas.
    Basado en metodología MAGERIT con compatibilidad legacy.
    """
    tipo: str = Field(
        description="Tipo de vulnerabilidad (personas, tecnología, procesos, física)"
    )
    descripcion: str = Field(
        description="Descripción detallada de la vulnerabilidad identificada"
    )
    severidad: str = Field(
        description="Nivel de severidad de la vulnerabilidad"
    )
    categoria: str = Field(
        description="Categoría específica dentro del tipo de vulnerabilidad"
    )
    recomendacion: str = Field(
        description="Recomendación específica para mitigar la vulnerabilidad"
    )
    # Campos avanzados (LangChain)
    cve_ids: Optional[List[str]] = Field(
        default=None,
        description="IDs de CVE relacionados si aplica"
    )
    mitre_attack_ids: Optional[List[str]] = Field(
        default=None,
        description="IDs de MITRE ATT&CK relacionados si aplica"
    )

    class Config:
        """Configuración del modelo."""
        from_attributes = True


class Impact(BaseModel):
    """
    Modelo unificado para impactos potenciales.
    Basado en Business Impact Analysis (BIA) con compatibilidad legacy.
    """
    tipo: str = Field(
        description="Tipo de impacto organizacional"
    )
    descripcion: str = Field(
        description="Descripción detallada del impacto potencial"
    )
    impacto: str = Field(
        description="Nivel de impacto en la organización"
    )
    recuperable: bool = Field(
        description="Si el impacto es recuperable o permanente"
    )
    tiempo_recuperacion: str = Field(
        description="Tiempo estimado para recuperación (RTO/RPO)"
    )
    # Campos avanzados (LangChain)
    probabilidad: Optional[str] = Field(
        default=None,
        description="Probabilidad de ocurrencia del impacto"
    )
    valor_riesgo: Optional[float] = Field(
        default=None,
        description="Valor numérico del riesgo (probabilidad × impacto)"
    )

    class Config:
        """Configuración del modelo."""
        from_attributes = True


class Control(BaseModel):
    """
    Modelo unificado para controles de seguridad recomendados.
    Basado en marcos como ISO 27001 y NIST con compatibilidad legacy.
    """
    tipo: str = Field(
        description="Tipo de control de seguridad"
    )
    descripcion: str = Field(
        description="Descripción detallada del control recomendado"
    )
    prioridad: str = Field(
        description="Prioridad de implementación del control"
    )
    costo_estimado: str = Field(
        description="Nivel de coste estimado para implementación"
    )
    tiempo_implementacion: str = Field(
        description="Tiempo estimado para implementación completa"
    )
    # Campos avanzados (LangChain)
    marco_referencia: Optional[List[str]] = Field(
        default=None,
        description="Marcos de referencia (ISO 27001, NIST, CIS Controls, etc.)"
    )
    kpis: Optional[List[str]] = Field(
        default=None,
        description="Indicadores clave de rendimiento para medir efectividad"
    )

    class Config:
        """Configuración del modelo."""
        from_attributes = True


class RiskLevel(BaseModel):
    """
    Modelo para nivel de riesgo calculado.
    """
    nivel: str = Field(
        description="Nivel de riesgo general"
    )
    puntuacion: float = Field(
        description="Puntuación numérica del riesgo (0-100)"
    )
    factores: List[str] = Field(
        description="Factores que contribuyen al nivel de riesgo"
    )
    justificacion: str = Field(
        description="Justificación del nivel de riesgo asignado"
    )

    class Config:
        """Configuración del modelo."""
        from_attributes = True


# ============================================================================
# MODELOS DE INCIDENTE (Unificados)
# ============================================================================

class Incident(BaseModel):
    """
    Modelo unificado representando un incidente de seguridad.
    Compatible con formato legacy y nuevas funcionalidades.
    """
    id: Optional[int] = None
    title: str
    description: str
    date_occurred: datetime
    severity: str = Field(
        pattern=r"^(low|medium|high|critical|baja|media|alta|critica)$"
    )
    status: str = Field(
        pattern=r"^(open|investigating|resolved|closed)$"
    )
    impact_type: str
    impact_description: str
    affected_systems: List[str]
    root_cause: Optional[str] = None
    mitigation_actions: List[str]
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        """Configuración del modelo."""
        from_attributes = True


# ============================================================================
# MODELOS DE REQUEST (Unificados)
# ============================================================================

class AnalysisRequest(BaseModel):
    """
    Modelo unificado para solicitud de análisis de incidente.
    Compatible con formato legacy y nuevas validaciones.
    """
    titulo: str = Field(
        min_length=3,
        max_length=200,
        description="Título descriptivo del incidente"
    )
    descripcion: str = Field(
        min_length=10,
        max_length=2000,
        description="Descripción detallada del incidente"
    )
    # Campos opcionales avanzados
    categoria_inicial: Optional[str] = Field(
        default=None,
        description="Categoría inicial sospechada del incidente"
    )
    urgencia: Optional[str] = Field(
        default="media",
        description="Nivel de urgencia del análisis"
    )
    contexto_adicional: Optional[str] = Field(
        default=None,
        description="Información adicional relevante para el análisis"
    )

    class Config:
        """Configuración del modelo."""
        from_attributes = True


# Alias para compatibilidad
IncidentAnalysisRequest = AnalysisRequest


# ============================================================================
# MODELOS DE RESPONSE (Unificados)
# ============================================================================

class AnalysisResponse(BaseModel):
    """
    Modelo unificado para respuesta de análisis de incidente.
    Compatible con formato legacy y nuevas funcionalidades avanzadas.
    """
    # Campos legacy (siempre presentes)
    status: str
    data: Dict[str, Any]
    
    # Campos avanzados opcionales (LangChain)
    id_analisis: Optional[str] = Field(
        default=None,
        description="Identificador único del análisis"
    )
    timestamp: Optional[datetime] = Field(
        default_factory=datetime.utcnow,
        description="Timestamp del análisis"
    )
    modelo_utilizado: Optional[str] = Field(
        default=None,
        description="Modelo de IA utilizado para el análisis"
    )
    nivel_riesgo: Optional[RiskLevel] = Field(
        default=None,
        description="Nivel de riesgo calculado para el incidente"
    )
    vulnerabilidades: Optional[List[Vulnerability]] = Field(
        default=None,
        description="Lista de vulnerabilidades identificadas"
    )
    impactos: Optional[List[Impact]] = Field(
        default=None,
        description="Lista de impactos potenciales"
    )
    controles: Optional[List[Control]] = Field(
        default=None,
        description="Lista de controles de seguridad recomendados"
    )
    resumen_ejecutivo: Optional[str] = Field(
        default=None,
        description="Resumen ejecutivo del análisis para directivos"
    )
    recomendaciones_inmediatas: Optional[List[str]] = Field(
        default=None,
        description="Lista de acciones inmediatas recomendadas"
    )
    plan_mitigacion: Optional[str] = Field(
        default=None,
        description="Plan de mitigación estructurado"
    )
    confianza_analisis: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Nivel de confianza del análisis (0-1)"
    )
    metadatos: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Metadatos adicionales del análisis"
    )

    class Config:
        """Configuración del modelo."""
        from_attributes = True


# Alias para compatibilidad
IncidentAnalysisResponse = AnalysisResponse


# ============================================================================
# MODELOS DE CONFIGURACIÓN
# ============================================================================

class LangChainAnalysisConfig(BaseModel):
    """
    Configuración para el análisis con LangChain.
    """
    modelo_principal: Literal["gpt-3.5-turbo", "gpt-4", "gpt-4.1-turbo", "gpt-4o"] = Field(
        default="gpt-4.1-turbo",
        description="Modelo principal para análisis críticos"
    )
    modelo_fallback: Literal["gpt-3.5-turbo", "gpt-4", "gpt-4.1-turbo"] = Field(
        default="gpt-3.5-turbo",
        description="Modelo de respaldo en caso de fallo"
    )
    temperatura: float = Field(
        default=0.3,
        ge=0.0,
        le=2.0,
        description="Temperatura del modelo (0 = determinístico, 2 = muy creativo)"
    )
    max_tokens: int = Field(
        default=2000,
        ge=100,
        le=4000,
        description="Máximo número de tokens en la respuesta"
    )
    usar_streaming: bool = Field(
        default=True,
        description="Habilitar streaming de respuestas"
    )
    usar_memoria: bool = Field(
        default=False,
        description="Habilitar memoria conversacional"
    )
    nivel_detalle: Literal["basico", "detallado", "experto"] = Field(
        default="detallado",
        description="Nivel de detalle en el análisis"
    )
    incluir_marcos_referencia: bool = Field(
        default=True,
        description="Incluir referencias a marcos de seguridad"
    )
    validar_con_cti: bool = Field(
        default=False,
        description="Validar análisis con Cyber Threat Intelligence"
    )

    class Config:
        """Configuración del modelo."""
        from_attributes = True


# ============================================================================
# FUNCIONES DE UTILIDAD Y COMPATIBILIDAD
# ============================================================================

def create_legacy_analysis_response(data: Dict[str, Any]) -> AnalysisResponse:
    """
    Crea una respuesta de análisis en formato legacy para compatibilidad.
    
    Args:
        data: Datos del análisis
        
    Returns:
        AnalysisResponse: Respuesta en formato legacy
    """
    return AnalysisResponse(
        status="success",
        data=data
    )


def create_advanced_analysis_response(
    id_analisis: str,
    modelo_utilizado: str,
    nivel_riesgo: RiskLevel,
    vulnerabilidades: List[Vulnerability],
    impactos: List[Impact],
    controles: List[Control],
    resumen_ejecutivo: str,
    recomendaciones_inmediatas: List[str],
    confianza_analisis: float,
    plan_mitigacion: Optional[str] = None,
    metadatos: Optional[Dict[str, Any]] = None
) -> AnalysisResponse:
    """
    Crea una respuesta de análisis avanzada con todas las características.
    
    Args:
        id_analisis: Identificador único
        modelo_utilizado: Modelo de IA usado
        nivel_riesgo: Nivel de riesgo calculado
        vulnerabilidades: Lista de vulnerabilidades
        impactos: Lista de impactos
        controles: Lista de controles
        resumen_ejecutivo: Resumen para directivos
        recomendaciones_inmediatas: Acciones inmediatas
        confianza_analisis: Confianza del análisis (0-1)
        plan_mitigacion: Plan de mitigación opcional
        metadatos: Metadatos adicionales
        
    Returns:
        AnalysisResponse: Respuesta completa
    """
    # Crear data dict para compatibilidad legacy
    data = {
        "risk_level": {
            "level": nivel_riesgo.nivel,
            "score": nivel_riesgo.puntuacion,
            "factors": nivel_riesgo.factores,
            "justification": nivel_riesgo.justificacion
        },
        "vulnerabilities": [vuln.dict() for vuln in vulnerabilidades],
        "impacts": [impact.dict() for impact in impactos],
        "controls": [control.dict() for control in controles],
        "executive_summary": resumen_ejecutivo,
        "immediate_recommendations": recomendaciones_inmediatas,
        "mitigation_plan": plan_mitigacion
    }
    
    return AnalysisResponse(
        status="success",
        data=data,
        id_analisis=id_analisis,
        modelo_utilizado=modelo_utilizado,
        nivel_riesgo=nivel_riesgo,
        vulnerabilidades=vulnerabilidades,
        impactos=impactos,
        controles=controles,
        resumen_ejecutivo=resumen_ejecutivo,
        recomendaciones_inmediatas=recomendaciones_inmediatas,
        plan_mitigacion=plan_mitigacion,
        confianza_analisis=confianza_analisis,
        metadatos=metadatos
    )


# ============================================================================
# EXPORTACIONES PARA COMPATIBILIDAD
# ============================================================================

__all__ = [
    # Enums
    "SeverityLevel",
    "VulnerabilityType", 
    "ImpactType",
    "ControlType",
    "Priority",
    "CostLevel",
    "IncidentStatus",
    # Modelos core
    "Vulnerability",
    "Impact",
    "Control",
    "RiskLevel",
    "Incident",
    # Request/Response
    "AnalysisRequest",
    "IncidentAnalysisRequest",  # Alias
    "AnalysisResponse",
    "IncidentAnalysisResponse",  # Alias
    # Configuración
    "LangChainAnalysisConfig",
    # Utilidades
    "create_legacy_analysis_response",
    "create_advanced_analysis_response"
]
