# 📚 RAG System - Risk-Guardian

Sistema modular de **Retrieval-Augmented Generation** para Risk-Guardian, especializado en conocimiento de ciberseguridad.

## 🏗️ **Arquitectura Modular**

```
src/services/rag/
├── __init__.py              # Exports principales y funciones singleton
├── core.py                  # Orquestador principal SecurityKnowledgeRAG
├── document_loader.py       # Carga y procesamiento de documentos
├── vector_store.py          # Gestión de embeddings y almacenamiento vectorial
├── retriever.py            # Sistema de búsqueda y recuperación semántica
└── README.md               # Esta documentación
```

---

## 🧩 **Módulos Especializados**

### **📄 `document_loader.py`** - SecurityDocumentLoader
- **Responsabilidad**: Carga y procesamiento de documentos
- **Características**:
  - Soporte para documentos de ciberseguridad (MAGERIT, OCTAVE, ISO 27001)
  - Clasificación automática por tipo de contenido
  - Text splitting optimizado para terminología técnica
  - Extracción de keywords específicos de seguridad
  - Metadata enriquecida con contexto

### **🗄️ `vector_store.py`** - SecurityVectorStore  
- **Responsabilidad**: Embeddings y almacenamiento vectorial
- **Características**:
  - OpenAI embeddings (text-embedding-ada-002)
  - Persistencia con Chroma DB
  - Cache inteligente con detección de cambios
  - Metadata especializada para dominio de ciberseguridad
  - Operaciones CRUD para documentos

### **🔍 `retriever.py`** - SecurityRetriever
- **Responsabilidad**: Búsqueda y recuperación semántica
- **Características**:
  - MMR (Maximal Marginal Relevance) para diversidad
  - Filtrado por metadata y tipos de documento
  - Búsqueda por metodología específica
  - Formateo optimizado para prompts
  - Tracking de estadísticas de uso

### **🎯 `core.py`** - SecurityKnowledgeRAG
- **Responsabilidad**: Orquestación principal
- **Características**:
  - Inicialización coordinada de todos los módulos
  - Health checks y monitoreo de estado
  - API unificada para todas las operaciones
  - Gestión de estadísticas centralizadas
  - Fallbacks y recuperación de errores

### **🚀 `__init__.py`** - API Pública
- **Responsabilidad**: Interfaz externa y funciones singleton
- **Características**:
  - Funciones convenientes para uso externo
  - Singleton pattern para instancia global
  - Compatibilidad con código existente
  - Exports organizados por funcionalidad

---

## 📋 **API Principal**

### **🔧 Funciones de Inicialización**
```python
from src.services.rag import get_rag_service, get_rag_health

# Obtener servicio (singleton)
rag = await get_rag_service()

# Verificar estado de salud
health = await get_rag_health()
```

### **🔍 Funciones de Búsqueda**
```python
from src.services.rag import search_security_knowledge, search_by_methodology

# Búsqueda general
results = await search_security_knowledge("vulnerabilidades", max_results=5)

# Búsqueda por metodología específica
magerit_results = await search_by_methodology("análisis riesgo", "MAGERIT", 3)
```

### **📊 Funciones de Utilidad**
```python
from src.services.rag import get_rag_stats, format_context_for_prompt

# Estadísticas del sistema
stats = await get_rag_stats()

# Formatear contexto para prompts
formatted = format_context_for_prompt(search_results)
```

---

## 🎯 **Ventajas de la Modularización**

### **🧹 Sin Redundancias**
- **Separación clara** de responsabilidades
- **Reutilización** de código entre módulos
- **Eliminación** de funcionalidades duplicadas
- **Interfaces** bien definidas entre componentes

### **🚫 Sin Simulaciones**
- **Funcionalidad real** en todos los módulos
- **Tests verificables** con datos reales
- **Operaciones auténticas** sin mocks innecesarios
- **Trazabilidad completa** del flujo de datos

### **⚡ Mantenibilidad**
- **Módulos independientes** fáciles de mantener
- **Testing granular** por componente
- **Debugging simplificado** por funcionalidad
- **Extensibilidad** sin afectar otros módulos

### **🔧 Flexibilidad**
- **Configuración específica** por módulo
- **Intercambio** de implementaciones
- **Escalabilidad** horizontal por componente
- **Optimización independiente** de cada parte

---

## 🧪 **Testing y Verificación**

### **Script de Pruebas**
```bash
# Ejecutar desde la raíz del proyecto
python test_rag.py
```

### **Verificaciones Incluidas**
- ✅ **Inicialización** de cada módulo
- ✅ **Carga de documentos** con metadata
- ✅ **Vector store** y persistencia
- ✅ **Búsquedas semánticas** con MMR
- ✅ **Health checks** automáticos
- ✅ **Estadísticas** en tiempo real

### **Tests por Módulo**
- **Document Loader**: Carga, clasificación, splitting
- **Vector Store**: Embeddings, persistencia, cache
- **Retriever**: Búsqueda, filtrado, ranking  
- **Core**: Orquestación, health, estadísticas
- **API**: Funciones públicas, singleton

---

## 📈 **Métricas y Monitoreo**

### **Estadísticas Disponibles**
```python
{
  "documents_loaded": 3,
  "chunks_created": 157,
  "initialization_time": 2.45,
  "retrieval_calls": 12,
  "vectorstore": {
    "total_documents": 157,
    "document_types": {"metodologia_riesgo": 45, "principios_seguridad": 67, ...},
    "cache_exists": true
  },
  "retriever": {
    "total_searches": 12,
    "avg_results_per_search": 4.2,
    "top_search_terms": {"vulnerabilidad": 3, "magerit": 2, ...}
  }
}
```

### **Health Check**
```python
{
  "status": "healthy",
  "components": {
    "initialized": true,
    "docs_accessible": true,
    "vector_store": true,
    "retriever": true,
    "embeddings": true
  },
  "test_search_successful": true
}
```

---

## 🔄 **Compatibilidad**

La nueva estructura modular mantiene **100% de compatibilidad** con el código existente:

```python
# Código existente (sigue funcionando)
from src.services.rag import get_rag_service, search_security_knowledge

# Nuevo código (funcionalidades adicionales)  
from src.services.rag import search_by_methodology, get_rag_health
```

---

## 🚀 **Próximas Mejoras**

- [ ] **Compresión contextual** con LLMChainExtractor
- [ ] **Embeddings híbridos** con modelos especializados
- [ ] **Reranking** con modelos específicos de ciberseguridad
- [ ] **Actualización incremental** de documentos
- [ ] **Métricas avanzadas** con LangSmith
- [ ] **Cache distribuido** para entornos multi-instancia

---

*La modularización elimina código redundante, simulaciones innecesarias y crea una base sólida para el crecimiento futuro del sistema RAG de Risk-Guardian.*
