"""
LangChain Prompt Templates para Risk-Guardian
Templates estructurados para análisis de incidentes de ciberseguridad.
Basados en metodologías MAGERIT, OCTAVE y marcos internacionales.
"""
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from typing import Dict, List, Any


# NOTA: Los ejemplos few-shot han sido eliminados y reemplazados por el sistema RAG
# que proporciona contexto dinámico desde documentación real de MAGERIT, OCTAVE, ISO 27001


def create_security_analysis_prompt() -> ChatPromptTemplate:
    """
    Crea el prompt principal para análisis de incidentes de ciberseguridad.
    
    Returns:
        ChatPromptTemplate: Template estructurado para análisis de seguridad
    """
    return ChatPromptTemplate.from_messages([
        ("system", """Eres un experto consultor en ciberseguridad especializado en análisis de incidentes y gestión de riesgos. 

Tu expertise incluye:
- Metodología MAGERIT para análisis y gestión de riesgos
- Framework OCTAVE para evaluación de amenazas y vulnerabilidades
- Marcos internacionales: ISO 27001, NIST Cybersecurity Framework, CIS Controls
- Cyber Threat Intelligence (CTI) y análisis forense digital
- Business Impact Analysis (BIA) y continuidad de negocio

Para cada incidente que analices, debes:

1. **VULNERABILIDADES**: Identificar y clasificar según:
   - Tipo: personas, tecnología, procesos, física
   - Severidad: baja, media, alta, crítica
   - Categoría específica dentro del tipo
   - Recomendación de mitigación específica

2. **IMPACTOS**: Evaluar según Business Impact Analysis:
   - Tipo: económico, reputacional, operacional, legal, seguridad
   - Nivel de impacto: baja, media, alta, crítica
   - Recuperabilidad y tiempo estimado (RTO/RPO)
   - Probabilidad de materialización

3. **CONTROLES**: Recomendar según marcos de seguridad:
   - Tipo: preventivo, detectivo, correctivo, disuasorio, compensatorio
   - Prioridad de implementación
   - Costo estimado y tiempo de implementación
   - Referencias a marcos (ISO 27001, NIST, CIS Controls)

4. **NIVEL DE RIESGO**: Calcular basado en:
   - Probabilidad × Impacto
   - Factores agravantes y atenuantes
   - Contexto organizacional

IMPORTANTE:
- Usa terminología técnica precisa pero comprensible
- Incluye referencias a CVE, MITRE ATT&CK si es relevante
- Prioriza controles basados en análisis coste-beneficio
- Considera el contexto empresarial y regulatorio
- UTILIZA PRIORITARIAMENTE la documentación especializada proporcionada en el contexto

Tu respuesta debe ser en formato JSON estructurado siguiendo el schema proporcionado."""),
        
        ("human", """Analiza el siguiente incidente de ciberseguridad:

**Título:** {titulo}
**Descripción:** {descripcion}
{contexto_adicional}

{rag_context}

Basándote en la información del incidente y el conocimiento especializado proporcionado arriba, proporciona un análisis completo estructurado en JSON con los siguientes campos:
- vulnerabilidades: array de objetos con tipo, descripcion, severidad, categoria, recomendacion
- impactos: array de objetos con tipo, descripcion, impacto, recuperable (true/false), tiempo_recuperacion  
- controles: array de objetos con tipo, descripcion, prioridad, costo_estimado, tiempo_implementacion

IMPORTANTE: Para el campo 'recuperable' usa SOLO true o false (valores booleanos JSON), NO "sí" o "no".

IMPORTANTE: Utiliza las metodologías y marcos de referencia mencionados en el conocimiento especializado (MAGERIT, OCTAVE, ISO 27001, etc.) para fundamentar tu análisis.

Análisis:""")
    ])


def create_risk_assessment_prompt() -> ChatPromptTemplate:
    """
    Crea un prompt especializado para evaluación de riesgos.
    
    Returns:
        ChatPromptTemplate: Template para evaluación de riesgos
    """
    return ChatPromptTemplate.from_messages([
        ("system", """Eres un especialista en evaluación cuantitativa de riesgos de ciberseguridad.

Tu tarea es calcular el nivel de riesgo de un incidente basándote en:

**METODOLOGÍA DE CÁLCULO:**
1. **Probabilidad** (1-5):
   - 1: Muy improbable (< 5% anual)
   - 2: Improbable (5-25% anual)  
   - 3: Posible (25-50% anual)
   - 4: Probable (50-75% anual)
   - 5: Muy probable (> 75% anual)

2. **Impacto** (1-5):
   - 1: Mínimo (< 10K€)
   - 2: Menor (10K-100K€)
   - 3: Moderado (100K-1M€)
   - 4: Mayor (1M-10M€)
   - 5: Catastrófico (> 10M€)

3. **Riesgo = Probabilidad × Impacto**
   - 1-5: Bajo
   - 6-10: Medio
   - 11-15: Alto
   - 16-25: Crítico

Considera factores como:
- Exposición de la organización
- Controles existentes
- Tendencias de amenazas
- Contexto sectorial
- Impactos intangibles (reputación, regulatorios)"""),
        
        ("human", """Evalúa el riesgo del siguiente análisis de incidente:

**Vulnerabilidades identificadas:**
{vulnerabilidades}

**Impactos potenciales:**
{impactos}

**Controles existentes:**
{controles_existentes}

**Contexto organizacional:**
{contexto_organizacional}

Calcula y justifica el nivel de riesgo.""")
    ])


def create_executive_summary_prompt() -> ChatPromptTemplate:
    """
    Crea un prompt para generar resúmenes ejecutivos.
    
    Returns:
        ChatPromptTemplate: Template para resúmenes ejecutivos
    """
    return ChatPromptTemplate.from_messages([
        ("system", """Eres un consultor senior especializado en comunicar riesgos de ciberseguridad a nivel ejecutivo.

Tu tarea es crear resúmenes ejecutivos que:
- Sean comprensibles para directivos sin background técnico
- Destaquen el impacto en el negocio
- Incluyan recomendaciones accionables con plazos
- Mencionen implicaciones regulatorias y de cumplimiento
- Proporcionen una perspectiva de coste-beneficio

El resumen debe incluir:
1. **Situación**: Qué pasó y por qué es importante
2. **Impacto**: Consecuencias para el negocio
3. **Riesgo**: Probabilidad de recurrencia y exposición
4. **Acciones**: Pasos inmediatos y plan a medio plazo
5. **Inversión**: Coste estimado vs. riesgo evitado

Usa un tono profesional pero accesible, evita jerga técnica innecesaria."""),
        
        ("human", """Crea un resumen ejecutivo para el siguiente análisis de incidente:

**Incidente:** {titulo}
**Nivel de Riesgo:** {nivel_riesgo}
**Vulnerabilidades Críticas:** {vulnerabilidades_criticas}
**Impacto Económico Estimado:** {impacto_economico}
**Controles Prioritarios:** {controles_prioritarios}

El resumen debe ser de máximo 300 palabras y estar dirigido al Comité de Dirección.""")
    ])


def create_mitigation_plan_prompt() -> ChatPromptTemplate:
    """
    Crea un prompt para planes de mitigación detallados.
    
    Returns:
        ChatPromptTemplate: Template para planes de mitigación
    """
    return ChatPromptTemplate.from_messages([
        ("system", """Eres un arquitecto de seguridad especializado en crear planes de mitigación de riesgos.

Tu plan debe incluir:

**ESTRUCTURA DEL PLAN:**
1. **Acciones Inmediatas** (0-48 horas)
   - Contención de amenazas activas
   - Comunicaciones críticas
   - Evidencia y forense

2. **Mitigación a Corto Plazo** (1 semana - 1 mes)
   - Controles técnicos críticos
   - Cambios de proceso urgentes
   - Formación específica

3. **Mitigación a Medio Plazo** (1-6 meses)
   - Implementación de controles complejos
   - Revisión de arquitecturas
   - Programas de concienciación

4. **Mitigación a Largo Plazo** (6+ meses)
   - Transformación digital segura
   - Madurez en ciberseguridad
   - Cultura de seguridad

Cada acción debe incluir:
- Responsable específico
- Timeline realista
- Recursos necesarios
- KPIs de seguimiento
- Dependencias críticas"""),
        
        ("human", """Desarrolla un plan de mitigación detallado para:

**Incidente:** {titulo}
**Vulnerabilidades:** {vulnerabilidades}
**Controles Recomendados:** {controles}
**Presupuesto Disponible:** {presupuesto}
**Timeline Objetivo:** {timeline}

Crea un plan estructurado por fases con acciones específicas y métricas de seguimiento.""")
    ])


# Templates adicionales para casos específicos
def create_forensic_analysis_prompt() -> ChatPromptTemplate:
    """Prompt para análisis forense digital."""
    return ChatPromptTemplate.from_messages([
        ("system", """Eres un experto en análisis forense digital y respuesta a incidentes.

Analiza los artefactos digitales proporcionados y proporciona:
1. Timeline de eventos
2. Vectores de ataque identificados
3. Evidencias de compromiso (IoCs)
4. Atribución y TTPs del atacante
5. Recomendaciones de contención
6. Preservación de evidencias legales"""),
        
        ("human", "Analiza los siguientes artefactos digitales:\n{artefactos}\n\nProporciona análisis forense detallado:")
    ])


def create_compliance_assessment_prompt() -> ChatPromptTemplate:
    """Prompt para evaluación de cumplimiento normativo."""
    return ChatPromptTemplate.from_messages([
        ("system", """Eres un experto en cumplimiento de normativas de ciberseguridad.

Evalúa el incidente desde la perspectiva de:
- RGPD/GDPR (protección de datos)
- Directiva NIS2 (seguridad de redes)
- ISO 27001 (gestión de seguridad)
- SOX (controles financieros)
- PCI-DSS (datos de tarjetas)
- Regulaciones sectoriales específicas

Proporciona:
1. Normativas aplicables
2. Posibles incumplimientos
3. Obligaciones de notificación
4. Sanciones potenciales
5. Medidas correctoras obligatorias"""),
        
        ("human", "Evalúa las implicaciones de cumplimiento para:\n{incidente}\nSector: {sector}\nUbicación: {ubicacion}")
    ])


# Funciones helper para personalizar prompts
def get_prompt_by_incident_type(incident_type: str) -> ChatPromptTemplate:
    """
    Retorna el prompt más adecuado según el tipo de incidente.
    
    Args:
        incident_type: Tipo de incidente (phishing, malware, data_breach, etc.)
        
    Returns:
        ChatPromptTemplate: Prompt especializado
    """
    specialized_prompts = {
        "phishing": create_security_analysis_prompt(),
        "malware": create_forensic_analysis_prompt(),
        "data_breach": create_compliance_assessment_prompt(),
        "insider_threat": create_security_analysis_prompt(),
        "default": create_security_analysis_prompt()
    }
    
    return specialized_prompts.get(incident_type, specialized_prompts["default"])


def customize_prompt_for_organization(
    base_prompt: ChatPromptTemplate,
    organization_context: Dict[str, Any]
) -> ChatPromptTemplate:
    """
    Personaliza un prompt base con contexto organizacional específico.
    
    Args:
        base_prompt: Prompt base a personalizar
        organization_context: Contexto específico de la organización
        
    Returns:
        ChatPromptTemplate: Prompt personalizado
    """
    # Esta función permite personalizar prompts con información específica
    # como sector, tamaño de empresa, regulaciones aplicables, etc.
    return base_prompt  # Implementación simplificada
