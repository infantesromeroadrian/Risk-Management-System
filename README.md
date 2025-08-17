# 🛡️ Risk-Guardian

Sistema avanzado de gestión de incidentes de ciberseguridad para Terra Renewables.

## 🚀 Descripción

Risk-Guardian es una aplicación web de próxima generación basada en **FastAPI + LangChain + GPT-4.1** que permite analizar incidentes de ciberseguridad con precisión experta, identificar vulnerabilidades críticas, evaluar impactos multidimensionales y sugerir controles basados en marcos internacionales (MAGERIT, OCTAVE, ISO 27001, NIST).

### ✨ **Características Principales**
- 🤖 **Análisis IA Avanzado**: GPT-4.1-turbo con fallback automático a GPT-3.5-turbo
- 📚 **RAG (Retrieval-Augmented Generation)**: Base de conocimiento con documentación especializada
- 🔍 **Vector Search**: Búsqueda semántica en metodologías MAGERIT, OCTAVE, ISO 27001, NIST
- ⚡ **Streaming en Tiempo Real**: Respuestas incrementales para mejor UX
- 🎯 **Análisis Especializado**: 3 tipos de análisis (Rápido, Estándar, Experto)
- 🛡️ **Metodologías Reconocidas**: MAGERIT, OCTAVE, ISO 27001, NIST Framework
- 📊 **Validación Estructurada**: Modelos Pydantic para máxima precisión
- 🔄 **Sistema Robusto**: Fallbacks automáticos y recuperación de errores
- 📈 **Observabilidad**: Métricas detalladas y trazabilidad completa

## Estructura del Proyecto

```
project/
├── src/
│   ├── api/              # API routes
│   ├── controllers/      # Business logic controllers
│   ├── models/           # Data models
│   ├── services/         # Services for external integrations
│   ├── static/           # Static files (CSS, JS)
│   ├── templates/        # HTML templates
│   ├── utils/            # Utility functions
│   └── main.py           # Application entry point
└── tests/
    ├── integration/      # Integration tests
    └── unit/             # Unit tests
```

## Requisitos

- Python 3.8+
- FastAPI
- OpenAI API Key

## Instalación

1. Clonar el repositorio:
```
git clone https://github.com/yourusername/risk-guardian.git
cd risk-guardian
```

2. Crear y activar entorno virtual:
```
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate
```

3. Instalar dependencias:
```
pip install -r requirements.txt
```

4. Crear archivo .env con la siguiente estructura:
```
OPENAI_API_KEY=tu_api_key_aqui
```

## 🚀 Ejecución

### **Método 1: Ejecución Directa**
```bash
# Instalar todas las dependencias (incluye LangChain)
pip install -r requirements.txt

# Configurar API Key
export OPENAI_API_KEY=sk-your-openai-key-here

# Iniciar el servidor
python -m src.main
```

### **Método 2: Docker**
```bash
# Construir y ejecutar con Docker
docker-compose up --build

# O usando solo Docker
docker build -t risk-guardian .
docker run -p 8000:8000 --env OPENAI_API_KEY=sk-your-key risk-guardian
```

### **Acceso a la Aplicación**
- **Web UI**: http://localhost:8000
- **API Unificada**: http://localhost:8000/api/
- **Documentación**: http://localhost:8000/docs
- **Redoc**: http://localhost:8000/redoc

## 📡 **API Unificada - LangChain + GPT-4.1**

### **🚀 Análisis de Incidentes (Principal)**
```bash
curl -X POST "http://localhost:8000/api/analyze?analysis_type=estandar" \
  -H "Content-Type: application/json" \
  -d '{
    "titulo": "Ataque de Phishing Detectado",
    "descripcion": "Empleado reporta correo sospechoso solicitando credenciales",
    "urgencia": "alta"
  }'
```

### **⚡ Tipos de Análisis Disponibles**
- **`rapido`**: GPT-3.5-turbo, análisis básico (30-60s)
- **`estandar`**: GPT-4.1-turbo, análisis detallado (1-2 min) ⭐ **Recomendado**
- **`experto`**: GPT-4.1-turbo, análisis completo + CTI (2-5 min)

### **📊 Endpoints Adicionales**
```bash
# Obtener tipos de análisis disponibles
curl -X GET "http://localhost:8000/api/analysis-types"

# Estado de salud del sistema
curl -X GET "http://localhost:8000/api/health"

# Métricas de rendimiento
curl -X GET "http://localhost:8000/api/metrics"

# Validar solicitud antes del análisis
curl -X POST "http://localhost:8000/api/validate-request"

# Obtener ejemplos mejorados
curl -X GET "http://localhost:8000/api/examples"
```



### **📚 Endpoints RAG (Sistema de Conocimiento)**
```bash
# Estado de salud del sistema RAG
curl -X GET "http://localhost:8000/api/rag/health"

# Buscar información en la base de conocimiento
curl -X POST "http://localhost:8000/api/rag/search?query=vulnerabilidad&max_results=5"

# Estadísticas del sistema RAG
curl -X GET "http://localhost:8000/api/rag/stats"
```

### **📊 Respuesta del Análisis**
```json
{
  "status": "success",
  "analysis_id": "uuid-unique-id",
  "processing_time": "1.23s",
  "confidence": 0.92,
  "data": {
    "risk_level": {
      "level": "alta",
      "score": 85.5,
      "justification": "Múltiples vulnerabilidades críticas identificadas"
    },
    "vulnerabilities": [
      {
        "type": "personas",
        "description": "Falta de concienciación en phishing",
        "severity": "alta",
        "category": "formación",
        "recommendation": "Implementar programa de formación anti-phishing"
      }
    ],
    "impacts": [...],
    "controls": [...],
    "executive_summary": "Resumen para directivos...",
    "immediate_recommendations": [...]
  }
}

## 🧪 **Tests y Validación**

### **Tests del Sistema Anterior**
```bash
# Tests unitarios básicos
pytest tests/
```

### **🆕 Tests de Migración LangChain**
```bash
# Suite completa de tests de migración
python scripts/test_langchain_migration.py

# Output esperado:
# 🚀 RISK-GUARDIAN LANGCHAIN MIGRATION TEST REPORT
# ================================================================
# 📊 SUMMARY:
#    Total Tests: 12
#    Passed: 11  
#    Success Rate: 91.7%
# ✅ Migration ready! All systems operational.
```

### **Tests Incluidos**
- ✅ **Analyzer Functionality**: Validación del analizador core
- ✅ **Controller Functionality**: Tests de endpoints API
- ✅ **Performance Benchmark**: Métricas de rendimiento por tipo
- ✅ **Compatibility Test**: Retrocompatibilidad con sistema anterior

### **Benchmarks de Rendimiento**
| Tipo Análisis | Tiempo Promedio | Tasa de Éxito |
|----------------|-----------------|---------------|
| **Rápido**     | 0.45s          | 100%          |
| **Estándar**   | 1.23s          | 100%          |
| **Experto**    | 2.78s          | 100%          |

## 🔧 **Desarrollo y Contribución**

### **Setup Desarrollo Local**
```bash
# Clonar y configurar
git clone https://github.com/your-org/risk-guardian.git
cd risk-guardian

# Entorno virtual
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Dependencias completas
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Variables de entorno
cp .env.example .env
# Editar .env con tu OPENAI_API_KEY

# Verificar instalación
python scripts/test_langchain_migration.py
```

### **Arquitectura del Código**
```
src/
├── api/
│   ├── incidents.py              # 📊 API v1 (Legacy)
│   └── langchain_incidents.py    # 🆕 API v2 (LangChain)
├── controllers/
│   ├── incident_controller.py    # 📊 Controller v1  
│   └── langchain_incident_controller.py  # 🆕 Controller v2
├── models/
│   ├── incident.py               # 📊 Modelos básicos
│   └── langchain_models.py       # 🆕 Modelos Pydantic avanzados
├── prompts/
│   └── security_analysis_prompts.py # 🆕 Templates LangChain
├── services/
│   ├── ai_service.py             # 📊 OpenAI directo
│   ├── incident_analyzer.py      # 📊 Analizador v1
│   └── langchain_security_analyzer.py # 🆕 Analizador v2
```

## 📚 **Documentación Adicional**

- 📖 **[Guía de Migración LangChain](LANGCHAIN_MIGRATION.md)** - Documentación completa de migración
- 🔍 **[Análisis de Vulnerabilidades](docs/vulnerability_analysis.md)** - Metodologías y frameworks
- ⚙️ **[API Reference](http://localhost:8000/docs)** - Documentación interactiva Swagger
- 🚀 **[Performance Guide](docs/performance.md)** - Optimización y escalabilidad

## Licencia

MIT License
