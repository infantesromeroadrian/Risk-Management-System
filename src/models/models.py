"""
Risk-Guardian Models - Versión Limpia y Minimalista
Solo modelos realmente utilizados, sin redundancias ni simulaciones.
"""
from datetime import datetime
from typing import List, Optional, Dict, Any, Literal
from pydantic import BaseModel, Field


# ============================================================================
# MODELOS DE REQUEST/RESPONSE (Solo los que se usan)
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


class AnalysisResponse(BaseModel):
    """
    Modelo para respuesta de análisis de incidente.
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


# ============================================================================
# CONFIGURACIÓN LANGCHAIN
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
# ALIASES DE COMPATIBILIDAD (Solo los necesarios)
# ============================================================================

# Solo aliases que se usan realmente
IncidentAnalysisRequest = AnalysisRequest
IncidentAnalysisResponse = AnalysisResponse


# ============================================================================
# EXPORTS MINIMALISTAS
# ============================================================================

__all__ = [
    # Modelos principales
    "AnalysisRequest",
    "AnalysisResponse", 
    "LangChainAnalysisConfig",
    # Aliases necesarios
    "IncidentAnalysisRequest",
    "IncidentAnalysisResponse"
]
