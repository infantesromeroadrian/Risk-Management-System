"""
Vector Store Manager para RAG System
Módulo especializado en gestión de embeddings y almacenamiento vectorial.
"""
from pathlib import Path
from typing import List, Dict, Any, Optional
import logging

from langchain_openai import OpenAIEmbeddings
from langchain_community.vectorstores import Chroma
from langchain_core.documents import Document

from src.utils.logger import setup_logger

logger = setup_logger(__name__)


class SecurityVectorStore:
    """
    Gestor de almacenamiento vectorial para documentos de ciberseguridad.
    
    Características:
    - Embeddings optimizados para contenido técnico
    - Persistencia automática con cache inteligente
    - Metadata enriquecida para mejor retrieval
    - Optimización específica para terminología de seguridad
    """
    
    def __init__(self, persist_directory: str = "vectorstore", openai_api_key: Optional[str] = None):
        """
        Inicializa el gestor de vector store.
        
        Args:
            persist_directory: Directorio para persistencia
            openai_api_key: API key de OpenAI
        """
        self.persist_directory = Path(persist_directory)
        self.openai_api_key = openai_api_key
        self.embeddings = None
        self.vectorstore = None
        
        logger.info(f"SecurityVectorStore inicializado - Persist: {self.persist_directory}")

    async def initialize_embeddings(self, api_key: Optional[str] = None) -> None:
        """
        Inicializa el modelo de embeddings.
        
        Args:
            api_key: API key de OpenAI (opcional)
        """
        try:
            self.embeddings = OpenAIEmbeddings(
                model="text-embedding-ada-002",
                openai_api_key=api_key or self.openai_api_key,
                chunk_size=1000,
                max_retries=3,
                request_timeout=30
            )
            
            logger.info("Embeddings inicializados: text-embedding-ada-002")
            
        except Exception as e:
            logger.error(f"Error inicializando embeddings: {str(e)}")
            raise

    async def create_vectorstore(self, documents: List[Document]) -> Chroma:
        """
        Crea un nuevo vector store con los documentos proporcionados.
        
        Args:
            documents: Lista de documentos a indexar
            
        Returns:
            Chroma: Vector store creado
        """
        try:
            if not self.embeddings:
                raise ValueError("Embeddings no inicializados")
            
            if not documents:
                raise ValueError("No hay documentos para indexar")
            
            # Asegurar que el directorio existe
            self.persist_directory.mkdir(parents=True, exist_ok=True)
            
            # Crear vector store con configuración optimizada
            self.vectorstore = Chroma.from_documents(
                documents=documents,
                embedding=self.embeddings,
                persist_directory=str(self.persist_directory),
                collection_name="security_knowledge",
                collection_metadata=self._get_collection_metadata()
            )
            
            logger.info(f"Vector store creado con {len(documents)} documentos")
            return self.vectorstore
            
        except Exception as e:
            logger.error(f"Error creando vector store: {str(e)}")
            raise

    def _get_collection_metadata(self) -> Dict[str, Any]:
        """
        Obtiene metadata para la colección del vector store.
        
        Returns:
            Dict: Metadata de la colección
        """
        return {
            "description": "Risk-Guardian Security Knowledge Base",
            "version": "1.0",
            "language": "es",
            "domain": "cybersecurity",
            "frameworks": "MAGERIT, OCTAVE, ISO27001, NIST",
            "content_types": "metodologias_riesgo, principios_seguridad, gestion_riesgo_ti, marcos_normativos, cumplimiento_normativo"
        }

    async def load_existing_vectorstore(self) -> Optional[Chroma]:
        """
        Carga un vector store existente desde el cache.
        
        Returns:
            Optional[Chroma]: Vector store cargado o None si no existe
        """
        try:
            if not self._cache_exists():
                logger.info("No existe cache del vector store")
                return None
            
            if not self.embeddings:
                raise ValueError("Embeddings no inicializados")
            
            self.vectorstore = Chroma(
                persist_directory=str(self.persist_directory),
                embedding_function=self.embeddings,
                collection_name="security_knowledge"
            )
            
            # Verificar que el vector store tiene contenido
            collection = self.vectorstore.get()
            if not collection["ids"]:
                logger.warning("Vector store existe pero está vacío")
                return None
            
            logger.info(f"Vector store cargado desde cache - {len(collection['ids'])} documentos")
            return self.vectorstore
            
        except Exception as e:
            logger.error(f"Error cargando vector store desde cache: {str(e)}")
            return None

    def persist_vectorstore(self) -> bool:
        """
        Persiste el vector store actual.
        
        Returns:
            bool: True si se persistió correctamente
        """
        try:
            if not self.vectorstore:
                logger.warning("No hay vector store para persistir")
                return False
            
            # Nota: Desde Chroma 0.4.x la persistencia es automática
            logger.info(f"Vector store persistido automáticamente en {self.persist_directory}")
            return True
            
        except Exception as e:
            logger.error(f"Error persistiendo vector store: {str(e)}")
            return False

    def _cache_exists(self) -> bool:
        """
        Verifica si existe cache del vector store.
        
        Returns:
            bool: True si existe cache
        """
        if not self.persist_directory.exists():
            return False
        
        # Verificar archivos específicos de Chroma
        required_files = [
            "chroma.sqlite3",
            "index"
        ]
        
        for file_name in required_files:
            file_path = self.persist_directory / file_name
            if not (file_path.exists() or file_path.is_dir()):
                return False
        
        return True

    def should_reindex(self, documents_path: Path) -> bool:
        """
        Determina si se debe reindexar basado en cambios en documentos.
        
        Args:
            documents_path: Ruta a los documentos fuente
            
        Returns:
            bool: True si se debe reindexar
        """
        if not self._cache_exists():
            return True
        
        try:
            # Obtener timestamp del cache
            cache_time = self.persist_directory.stat().st_mtime
            
            # Verificar si algún documento es más reciente
            for doc_file in documents_path.glob("**/*.txt"):
                if doc_file.stat().st_mtime > cache_time:
                    logger.info(f"Documento modificado detectado: {doc_file.name}")
                    return True
            
            return False
            
        except Exception as e:
            logger.warning(f"Error verificando timestamps: {str(e)}")
            return False  # En caso de duda, usar cache existente

    async def add_documents(self, documents: List[Document]) -> bool:
        """
        Añade documentos al vector store existente.
        
        Args:
            documents: Lista de documentos a añadir
            
        Returns:
            bool: True si se añadieron correctamente
        """
        try:
            if not self.vectorstore:
                logger.error("Vector store no inicializado")
                return False
            
            if not documents:
                logger.warning("No hay documentos para añadir")
                return False
            
            # Añadir documentos al vector store
            self.vectorstore.add_documents(documents)
            
            # Persistir cambios
            self.persist_vectorstore()
            
            logger.info(f"Añadidos {len(documents)} documentos al vector store")
            return True
            
        except Exception as e:
            logger.error(f"Error añadiendo documentos: {str(e)}")
            return False

    async def update_document(self, document_id: str, new_document: Document) -> bool:
        """
        Actualiza un documento específico en el vector store.
        
        Args:
            document_id: ID del documento a actualizar
            new_document: Nuevo documento
            
        Returns:
            bool: True si se actualizó correctamente
        """
        try:
            if not self.vectorstore:
                logger.error("Vector store no inicializado")
                return False
            
            # Para Chroma, necesitamos eliminar y añadir
            # ya que no soporta actualización directa
            self.vectorstore.delete([document_id])
            self.vectorstore.add_documents([new_document])
            
            self.persist_vectorstore()
            
            logger.info(f"Documento {document_id} actualizado")
            return True
            
        except Exception as e:
            logger.error(f"Error actualizando documento {document_id}: {str(e)}")
            return False

    def get_vectorstore_stats(self) -> Dict[str, Any]:
        """
        Obtiene estadísticas del vector store.
        
        Returns:
            Dict: Estadísticas detalladas
        """
        try:
            if not self.vectorstore:
                return {
                    "status": "not_initialized",
                    "total_documents": 0
                }
            
            collection = self.vectorstore.get()
            
            # Calcular estadísticas de metadata
            doc_types = {}
            languages = set()
            
            for metadata in collection.get("metadatas", []):
                if metadata:
                    doc_type = metadata.get("document_type", "unknown")
                    doc_types[doc_type] = doc_types.get(doc_type, 0) + 1
                    
                    language = metadata.get("language", "unknown")
                    languages.add(language)
            
            return {
                "status": "initialized",
                "total_documents": len(collection["ids"]) if collection["ids"] else 0,
                "collection_name": "security_knowledge",
                "persist_directory": str(self.persist_directory),
                "cache_exists": self._cache_exists(),
                "document_types": doc_types,
                "languages": list(languages),
                "embeddings_model": "text-embedding-ada-002"
            }
            
        except Exception as e:
            logger.error(f"Error obteniendo estadísticas: {str(e)}")
            return {
                "status": "error",
                "error": str(e)
            }

    async def cleanup_vectorstore(self) -> bool:
        """
        Limpia y reinicia el vector store.
        
        Returns:
            bool: True si se limpió correctamente
        """
        try:
            # Eliminar archivos de cache
            if self.persist_directory.exists():
                import shutil
                shutil.rmtree(self.persist_directory)
                logger.info(f"Cache eliminado: {self.persist_directory}")
            
            # Reiniciar referencias
            self.vectorstore = None
            
            return True
            
        except Exception as e:
            logger.error(f"Error limpiando vector store: {str(e)}")
            return False
