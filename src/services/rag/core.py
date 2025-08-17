"""
Core Module para RAG System
Orquestador principal del sistema de Retrieval-Augmented Generation.
"""
from pathlib import Path
from typing import List, Dict, Any, Optional
import logging
from datetime import datetime

from .document_loader import SecurityDocumentLoader
from .vector_store import SecurityVectorStore
from .retriever import SecurityRetriever

from src.utils.config import load_config
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


class SecurityKnowledgeRAG:
    """
    Sistema RAG principal para conocimiento de ciberseguridad.
    
    Orquesta todos los componentes:
    - SecurityDocumentLoader: Carga y procesamiento de documentos
    - SecurityVectorStore: Embeddings y almacenamiento vectorial  
    - SecurityRetriever: Búsqueda y recuperación semántica
    
    Sin código redundante, sin simulaciones, solo funcionalidad real.
    """
    
    def __init__(self, docs_path: str = "docs", persist_directory: str = "vectorstore"):
        """
        Inicializa el sistema RAG principal.
        
        Args:
            docs_path: Ruta a los documentos fuente
            persist_directory: Directorio para cache vectorial
        """
        self.docs_path = Path(docs_path)
        self.persist_directory = Path(persist_directory)
        self.config = load_config()
        
        # Componentes especializados
        self.document_loader = SecurityDocumentLoader(str(self.docs_path))
        self.vector_store = SecurityVectorStore(str(self.persist_directory))
        self.retriever = None
        
        # Estado del sistema
        self.is_initialized = False
        self.initialization_time = None
        
        # Estadísticas centralizadas
        self.stats = {
            "documents_loaded": 0,
            "chunks_created": 0,
            "initialization_time": None,
            "retrieval_calls": 0,
            "last_search": None
        }
        
        logger.info(f"SecurityKnowledgeRAG inicializado - Docs: {self.docs_path}")

    async def initialize(self) -> bool:
        """
        Inicializa el sistema RAG completo.
        
        Returns:
            bool: True si se inicializa correctamente
        """
        try:
            start_time = datetime.utcnow()
            logger.info("Iniciando sistema RAG...")
            
            # 1. Inicializar embeddings
            await self._initialize_embeddings()
            
            # 2. Cargar o crear vector store
            success = await self._setup_vector_store()
            if not success:
                return False
            
            # 3. Configurar retriever
            await self._setup_retriever()
            
            # 4. Finalizar inicialización
            end_time = datetime.utcnow()
            self.initialization_time = (end_time - start_time).total_seconds()
            self.stats["initialization_time"] = self.initialization_time
            self.is_initialized = True
            
            logger.info(f"RAG inicializado en {self.initialization_time:.2f}s - "
                       f"{self.stats['documents_loaded']} docs, {self.stats['chunks_created']} chunks")
            return True
            
        except Exception as e:
            logger.error(f"Error inicializando RAG: {str(e)}")
            return False

    async def _initialize_embeddings(self) -> None:
        """Inicializa el modelo de embeddings."""
        api_key = self.config.get("openai_api_key")  # ✅ CORREGIDO: usar lowercase
        if not api_key:
            raise ValueError("OPENAI_API_KEY no configurada en variables de entorno")
        
        await self.vector_store.initialize_embeddings(api_key)
        logger.info("Embeddings inicializados")

    async def _setup_vector_store(self) -> bool:
        """
        Configura el vector store (carga desde cache o crea nuevo).
        
        Returns:
            bool: True si se configuró correctamente
        """
        try:
            # Intentar cargar desde cache
            vectorstore = await self.vector_store.load_existing_vectorstore()
            
            if vectorstore and not self.vector_store.should_reindex(self.docs_path):
                logger.info("Vector store cargado desde cache")
                stats = self.vector_store.get_vectorstore_stats()
                self.stats["chunks_created"] = stats.get("total_documents", 0)
                return True
            
            # Crear nuevo vector store
            logger.info("Creando nuevo vector store...")
            
            # Cargar documentos
            documents = await self.document_loader.load_all_documents()
            self.stats["documents_loaded"] = len(documents)
            
            if not documents:
                logger.error("No se encontraron documentos para indexar")
                return False
            
            # Dividir en chunks
            chunks = await self.document_loader.split_documents(documents)
            self.stats["chunks_created"] = len(chunks)
            
            # Crear vector store
            vectorstore = await self.vector_store.create_vectorstore(chunks)
            if not vectorstore:
                return False
            
            # Persistir
            self.vector_store.persist_vectorstore()
            
            logger.info(f"Nuevo vector store creado con {len(chunks)} chunks")
            return True
            
        except Exception as e:
            logger.error(f"Error configurando vector store: {str(e)}")
            return False

    async def _setup_retriever(self) -> None:
        """Configura el sistema de retrieval."""
        if not self.vector_store.vectorstore:
            raise ValueError("Vector store no disponible")
        
        self.retriever = SecurityRetriever(self.vector_store.vectorstore)
        
        # Configurar con parámetros optimizados para ciberseguridad
        self.retriever.configure_retriever(
            search_type="mmr",
            k=8,           # Recuperar 8 chunks
            fetch_k=16,    # Buscar en 16 candidatos
            lambda_mult=0.7  # Balance relevancia/diversidad
        )
        
        logger.info("Retriever configurado")

    async def search_relevant_context(
        self, 
        query: str, 
        max_chunks: int = 5,
        document_types: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Busca contexto relevante para una consulta.
        
        Args:
            query: Consulta de búsqueda
            max_chunks: Máximo número de chunks a retornar
            document_types: Filtrar por tipos de documento específicos
            
        Returns:
            List[Dict]: Lista de chunks relevantes
        """
        try:
            if not self.is_initialized:
                raise ValueError("Sistema RAG no inicializado")
            
            # Realizar búsqueda
            if document_types:
                results = await self.retriever.search_by_document_type(
                    query, document_types, max_chunks
                )
            else:
                results = await self.retriever.search_documents(query, max_chunks)
            
            # Actualizar estadísticas
            self.stats["retrieval_calls"] += 1
            self.stats["last_search"] = {
                "query": query[:50],
                "results_count": len(results),
                "timestamp": datetime.utcnow().isoformat()
            }
            
            logger.info(f"Búsqueda completada: {len(results)} chunks para '{query[:30]}...'")
            return results
            
        except Exception as e:
            logger.error(f"Error en búsqueda de contexto: {str(e)}")
            return []

    def format_context_for_prompt(self, context_chunks: List[Dict[str, Any]]) -> str:
        """
        Formatea el contexto para uso en prompts.
        
        Args:
            context_chunks: Lista de chunks de contexto
            
        Returns:
            str: Contexto formateado
        """
        if not context_chunks:
            return ""
        
        return self.retriever.format_context_for_prompt(context_chunks)

    async def search_by_methodology(self, query: str, methodology: str, max_results: int = 5) -> List[Dict[str, Any]]:
        """
        Busca información específica de una metodología.
        
        Args:
            query: Consulta de búsqueda
            methodology: Metodología específica (MAGERIT, OCTAVE, etc.)
            max_results: Máximo número de resultados
            
        Returns:
            List[Dict]: Resultados específicos de la metodología
        """
        methodology_keywords = {
            "MAGERIT": ["magerit", "activo", "amenaza", "vulnerabilidad", "impacto", "riesgo"],
            "OCTAVE": ["octave", "asset", "threat", "vulnerability"],
            "ISO27001": ["iso", "27001", "sgsi", "control", "anexo"],
            "NIST": ["nist", "framework", "cybersecurity", "function"]
        }
        
        keywords = methodology_keywords.get(methodology.upper(), [methodology.lower()])
        enhanced_query = f"{query} {methodology}"
        
        return await self.retriever.search_by_keywords(enhanced_query, keywords, max_results)

    async def get_document_types_available(self) -> List[str]:
        """
        Obtiene los tipos de documentos disponibles.
        
        Returns:
            List[str]: Lista de tipos de documento
        """
        try:
            if not self.is_initialized:
                return []
            
            stats = self.vector_store.get_vectorstore_stats()
            return list(stats.get("document_types", {}).keys())
            
        except Exception as e:
            logger.error(f"Error obteniendo tipos de documento: {str(e)}")
            return []

    def get_stats(self) -> Dict[str, Any]:
        """
        Obtiene estadísticas completas del sistema RAG.
        
        Returns:
            Dict: Estadísticas centralizadas
        """
        base_stats = {
            **self.stats,
            "is_initialized": self.is_initialized,
            "docs_path": str(self.docs_path),
            "persist_directory": str(self.persist_directory)
        }
        
        # Añadir estadísticas de componentes si están disponibles
        if self.vector_store:
            vectorstore_stats = self.vector_store.get_vectorstore_stats()
            base_stats["vectorstore"] = vectorstore_stats
        
        if self.retriever:
            retriever_stats = self.retriever.get_retriever_stats()
            base_stats["retriever"] = retriever_stats
        
        return base_stats

    async def health_check(self) -> Dict[str, Any]:
        """
        Verifica el estado de salud del sistema completo.
        
        Returns:
            Dict: Estado de salud detallado
        """
        try:
            health = {
                "status": "healthy",
                "timestamp": datetime.utcnow().isoformat(),
                "components": {
                    "initialized": self.is_initialized,
                    "docs_accessible": self.docs_path.exists(),
                    "vector_store": self.vector_store.vectorstore is not None,
                    "retriever": self.retriever is not None,
                    "embeddings": self.vector_store.embeddings is not None
                },
                "stats": self.get_stats()
            }
            
            # Test de búsqueda básica
            if self.retriever and self.is_initialized:
                try:
                    test_results = await self.search_relevant_context("test", max_chunks=1)
                    health["test_search_successful"] = len(test_results) > 0
                except:
                    health["test_search_successful"] = False
            else:
                health["test_search_successful"] = False
            
            # Determinar estado general
            if not all(health["components"].values()):
                health["status"] = "degraded"
                
            if not health["test_search_successful"]:
                health["status"] = "degraded"
            
            return health
            
        except Exception as e:
            logger.error(f"Error en health check: {str(e)}")
            return {
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
                "components": {},
                "stats": {}
            }

    async def cleanup(self) -> bool:
        """
        Limpia recursos del sistema RAG.
        
        Returns:
            bool: True si se limpió correctamente
        """
        try:
            logger.info("Limpiando recursos RAG...")
            
            # Limpiar vector store si es necesario
            if self.vector_store:
                await self.vector_store.cleanup_vectorstore()
            
            # Reiniciar estado
            self.is_initialized = False
            self.initialization_time = None
            self.retriever = None
            
            # Reiniciar estadísticas
            self.stats = {
                "documents_loaded": 0,
                "chunks_created": 0,
                "initialization_time": None,
                "retrieval_calls": 0,
                "last_search": None
            }
            
            logger.info("Recursos RAG limpiados")
            return True
            
        except Exception as e:
            logger.error(f"Error limpiando recursos: {str(e)}")
            return False

    async def reinitialize(self, force_reindex: bool = False) -> bool:
        """
        Reinicializa el sistema RAG.
        
        Args:
            force_reindex: Forzar reindexación completa
            
        Returns:
            bool: True si se reinicializó correctamente
        """
        try:
            logger.info("Reinicializando sistema RAG...")
            
            # Limpiar si se fuerza reindexación
            if force_reindex:
                await self.cleanup()
            
            # Reinicializar
            return await self.initialize()
            
        except Exception as e:
            logger.error(f"Error en reinicialización: {str(e)}")
            return False
