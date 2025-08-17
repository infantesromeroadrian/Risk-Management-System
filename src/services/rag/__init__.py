"""
RAG Package para Risk-Guardian
Sistema modular de Retrieval-Augmented Generation para ciberseguridad.

Exports principales:
- SecurityKnowledgeRAG: Clase principal
- get_rag_service: Función singleton
- search_security_knowledge: Función de búsqueda conveniente
"""
from typing import List, Dict, Any, Optional
import logging

from .core import SecurityKnowledgeRAG
from .document_loader import SecurityDocumentLoader
from .vector_store import SecurityVectorStore
from .retriever import SecurityRetriever

from src.utils.logger import setup_logger

logger = setup_logger(__name__)

# Singleton instance para uso global
_rag_instance: Optional[SecurityKnowledgeRAG] = None


async def get_rag_service(
    docs_path: str = "docs", 
    persist_directory: str = "vectorstore",
    force_reinit: bool = False
) -> SecurityKnowledgeRAG:
    """
    Obtiene la instancia singleton del servicio RAG.
    
    Args:
        docs_path: Ruta a los documentos (solo para primera inicialización)
        persist_directory: Directorio de persistencia (solo para primera inicialización)
        force_reinit: Forzar reinicialización
        
    Returns:
        SecurityKnowledgeRAG: Instancia del servicio RAG
        
    Raises:
        RuntimeError: Si no se puede inicializar el servicio
    """
    global _rag_instance
    
    try:
        # Reinicializar si se solicita
        if force_reinit and _rag_instance:
            logger.info("Forzando reinicialización del servicio RAG")
            await _rag_instance.cleanup()
            _rag_instance = None
        
        # Crear nueva instancia si no existe
        if _rag_instance is None:
            logger.info("Creando nueva instancia del servicio RAG")
            _rag_instance = SecurityKnowledgeRAG(docs_path, persist_directory)
            
            success = await _rag_instance.initialize()
            if not success:
                _rag_instance = None
                raise RuntimeError("No se pudo inicializar el servicio RAG")
            
            logger.info("Servicio RAG inicializado correctamente")
        
        return _rag_instance
        
    except Exception as e:
        logger.error(f"Error obteniendo servicio RAG: {str(e)}")
        _rag_instance = None
        raise RuntimeError(f"Error inicializando servicio RAG: {str(e)}")


async def search_security_knowledge(
    query: str, 
    max_results: int = 5,
    document_types: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    """
    Función conveniente para buscar en la base de conocimiento.
    
    Args:
        query: Consulta de búsqueda
        max_results: Máximo número de resultados
        document_types: Filtrar por tipos de documento específicos
        
    Returns:
        List[Dict]: Resultados de la búsqueda
        
    Raises:
        RuntimeError: Si el servicio RAG no está disponible
    """
    try:
        rag_service = await get_rag_service()
        return await rag_service.search_relevant_context(
            query, max_results, document_types
        )
        
    except Exception as e:
        logger.error(f"Error en búsqueda de conocimiento: {str(e)}")
        return []


async def search_by_methodology(
    query: str, 
    methodology: str,
    max_results: int = 5
) -> List[Dict[str, Any]]:
    """
    Busca información específica de una metodología.
    
    Args:
        query: Consulta de búsqueda
        methodology: Metodología (MAGERIT, OCTAVE, ISO27001, NIST)
        max_results: Máximo número de resultados
        
    Returns:
        List[Dict]: Resultados específicos de la metodología
    """
    try:
        rag_service = await get_rag_service()
        return await rag_service.search_by_methodology(query, methodology, max_results)
        
    except Exception as e:
        logger.error(f"Error buscando por metodología {methodology}: {str(e)}")
        return []


def format_context_for_prompt(context_chunks: List[Dict[str, Any]]) -> str:
    """
    Formatea contexto para uso en prompts (función sincrónica).
    
    Args:
        context_chunks: Lista de chunks de contexto
        
    Returns:
        str: Contexto formateado para prompt
    """
    if not context_chunks:
        return ""
    
    try:
        formatted_lines = []
        formatted_lines.append("=== CONOCIMIENTO DE CIBERSEGURIDAD ===")
        
        for i, chunk in enumerate(context_chunks, 1):
            doc_type = chunk["metadata"].get("document_type", "").replace("_", " ").title()
            filename = chunk["metadata"].get("filename", "").replace(".txt", "")
            
            formatted_lines.append(f"\n--- Fuente {i}: {doc_type} ({filename}) ---")
            formatted_lines.append(chunk["content"].strip())
        
        formatted_lines.append("\n=== FIN DEL CONOCIMIENTO ===\n")
        
        return "\n".join(formatted_lines)
        
    except Exception as e:
        logger.error(f"Error formateando contexto: {str(e)}")
        return ""


async def get_rag_health() -> Dict[str, Any]:
    """
    Obtiene el estado de salud del sistema RAG.
    
    Returns:
        Dict: Estado de salud del sistema
    """
    try:
        # Intentar obtener servicio sin inicializar
        if _rag_instance and _rag_instance.is_initialized:
            return await _rag_instance.health_check()
        else:
            return {
                "status": "not_initialized",
                "message": "Servicio RAG no inicializado",
                "components": {
                    "initialized": False
                }
            }
            
    except Exception as e:
        logger.error(f"Error en health check: {str(e)}")
        return {
            "status": "error",
            "error": str(e),
            "components": {}
        }


async def get_rag_stats() -> Dict[str, Any]:
    """
    Obtiene estadísticas del sistema RAG.
    
    Returns:
        Dict: Estadísticas del sistema
    """
    try:
        if _rag_instance:
            return _rag_instance.get_stats()
        else:
            return {
                "status": "not_initialized",
                "documents_loaded": 0,
                "chunks_created": 0,
                "retrieval_calls": 0
            }
            
    except Exception as e:
        logger.error(f"Error obteniendo estadísticas: {str(e)}")
        return {"error": str(e)}


async def reset_rag_service() -> bool:
    """
    Reinicia el servicio RAG completamente.
    
    Returns:
        bool: True si se reinició correctamente
    """
    global _rag_instance
    
    try:
        if _rag_instance:
            await _rag_instance.cleanup()
        
        _rag_instance = None
        logger.info("Servicio RAG reiniciado")
        return True
        
    except Exception as e:
        logger.error(f"Error reiniciando servicio RAG: {str(e)}")
        return False


# Funciones de compatibilidad con el código existente
async def get_document_types() -> List[str]:
    """
    Obtiene los tipos de documentos disponibles.
    
    Returns:
        List[str]: Lista de tipos de documento
    """
    try:
        rag_service = await get_rag_service()
        return await rag_service.get_document_types_available()
        
    except Exception as e:
        logger.error(f"Error obteniendo tipos de documento: {str(e)}")
        return []


async def test_rag_system(test_queries: List[str] = None) -> Dict[str, Any]:
    """
    Ejecuta pruebas del sistema RAG.
    
    Args:
        test_queries: Lista de consultas de prueba
        
    Returns:
        Dict: Resultados de las pruebas
    """
    if test_queries is None:
        test_queries = [
            "vulnerabilidad en sistemas",
            "metodología MAGERIT",
            "principios de seguridad", 
            "análisis de riesgo",
            "controles preventivos"
        ]
    
    try:
        rag_service = await get_rag_service()
        if not rag_service.retriever:
            return {"error": "Retriever no disponible"}
        
        return await rag_service.retriever.test_retrieval(test_queries)
        
    except Exception as e:
        logger.error(f"Error en pruebas RAG: {str(e)}")
        return {"error": str(e)}


# Exports principales
__all__ = [
    # Clases principales
    "SecurityKnowledgeRAG",
    "SecurityDocumentLoader", 
    "SecurityVectorStore",
    "SecurityRetriever",
    
    # Funciones principales
    "get_rag_service",
    "search_security_knowledge",
    "search_by_methodology",
    "format_context_for_prompt",
    
    # Utilidades y estado
    "get_rag_health",
    "get_rag_stats", 
    "reset_rag_service",
    "get_document_types",
    "test_rag_system"
]
