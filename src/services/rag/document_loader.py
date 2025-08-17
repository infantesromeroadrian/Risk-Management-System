"""
Document Loader para RAG System
Módulo especializado en carga y procesamiento de documentos de ciberseguridad.
"""
from pathlib import Path
from typing import List, Dict, Any
import logging

from langchain_community.document_loaders import TextLoader, DirectoryLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_core.documents import Document

from src.utils.logger import setup_logger

logger = setup_logger(__name__)


class SecurityDocumentLoader:
    """
    Cargador especializado para documentos de ciberseguridad.
    
    Características:
    - Carga documentos de metodologías (MAGERIT, OCTAVE, ISO 27001)
    - Clasificación automática por tipo de contenido
    - Extracción de keywords específicos de ciberseguridad
    - Text splitting optimizado para contenido técnico
    """
    
    def __init__(self, docs_path: str = "docs"):
        """
        Inicializa el cargador de documentos.
        
        Args:
            docs_path: Ruta a los documentos fuente
        """
        self.docs_path = Path(docs_path)
        self.security_keywords = [
            "magerit", "octave", "vulnerabilidad", "amenaza", "riesgo", "impacto",
            "control", "salvaguarda", "activo", "confidencialidad", "integridad",
            "disponibilidad", "iso", "nist", "ens", "ciberseguridad", "framework",
            "metodología", "análisis", "gestión", "evaluación", "mitigación",
            "compliance", "auditoria", "incidente", "contingencia"
        ]
        
        logger.info(f"SecurityDocumentLoader inicializado - Path: {self.docs_path}")

    async def load_all_documents(self) -> List[Document]:
        """
        Carga todos los documentos de la carpeta docs.
        
        Returns:
            List[Document]: Lista de documentos cargados con metadata enriquecida
        """
        try:
            if not self.docs_path.exists():
                raise FileNotFoundError(f"Directorio de documentos no encontrado: {self.docs_path}")
            
            # Usar DirectoryLoader para cargar archivos de texto
            loader = DirectoryLoader(
                str(self.docs_path),
                glob="**/*.txt",
                loader_cls=TextLoader,
                loader_kwargs={"encoding": "utf-8"},
                show_progress=True,
                use_multithreading=True
            )
            
            raw_documents = loader.load()
            
            # Enriquecer metadata de documentos
            enriched_documents = []
            for doc in raw_documents:
                enriched_doc = self._enrich_document_metadata(doc)
                enriched_documents.append(enriched_doc)
            
            logger.info(f"Cargados {len(enriched_documents)} documentos")
            return enriched_documents
            
        except Exception as e:
            logger.error(f"Error cargando documentos: {str(e)}")
            raise

    def _enrich_document_metadata(self, doc: Document) -> Document:
        """
        Enriquece los metadatos de un documento.
        
        Args:
            doc: Documento original
            
        Returns:
            Document: Documento con metadata enriquecida
        """
        file_path = Path(doc.metadata.get("source", ""))
        
        doc.metadata.update({
            "filename": file_path.name,
            "document_type": self._classify_document(file_path.name),
            "content_length": len(doc.page_content),
            "language": "es",
            "domain": "cybersecurity",
            "keywords_count": len(self._extract_keywords(doc.page_content))
        })
        
        return doc

    def _classify_document(self, filename: str) -> str:
        """
        Clasifica el tipo de documento basado en el nombre del archivo.
        
        Args:
            filename: Nombre del archivo
            
        Returns:
            str: Tipo de documento clasificado
        """
        filename_lower = filename.lower()
        
        # Clasificación basada en contenido conocido
        if "magerit" in filename_lower or "medicion_riesgo" in filename_lower:
            return "metodologia_riesgo"
        elif "principios" in filename_lower:
            return "principios_seguridad"
        elif "riesgo" in filename_lower and "ti" in filename_lower:
            return "gestion_riesgo_ti"
        elif "marco" in filename_lower or "framework" in filename_lower:
            return "marcos_normativos"
        elif "compliance" in filename_lower or "cumplimiento" in filename_lower:
            return "cumplimiento_normativo"
        else:
            return "documentacion_general"

    def create_text_splitter(self) -> RecursiveCharacterTextSplitter:
        """
        Crea un text splitter optimizado para documentos de ciberseguridad.
        
        Returns:
            RecursiveCharacterTextSplitter: Splitter configurado
        """
        return RecursiveCharacterTextSplitter(
            chunk_size=1000,        # Tamaño óptimo para contexto técnico
            chunk_overlap=200,      # Overlap para mantener continuidad
            length_function=len,
            separators=[
                "\n\n# ",          # Headers nivel 1
                "\n\n## ",         # Headers nivel 2
                "\n\n### ",        # Headers nivel 3
                "\n\n**",          # Texto en negrita (secciones)
                "\n\n",            # Párrafos
                "\n",              # Líneas
                ". ",              # Fin de oraciones
                " "                # Espacios (última opción)
            ],
            add_start_index=True    # Añadir índice de inicio para trazabilidad
        )

    async def split_documents(self, documents: List[Document]) -> List[Document]:
        """
        Divide documentos en chunks optimizados con metadata enriquecida.
        
        Args:
            documents: Lista de documentos a dividir
            
        Returns:
            List[Document]: Lista de chunks con metadata
        """
        text_splitter = self.create_text_splitter()
        all_chunks = []
        
        for doc in documents:
            chunks = text_splitter.split_documents([doc])
            
            # Enriquecer metadata de chunks
            for i, chunk in enumerate(chunks):
                chunk.metadata.update({
                    "chunk_id": f"{doc.metadata['filename']}_{i}",
                    "chunk_index": i,
                    "total_chunks": len(chunks),
                    "keywords": ", ".join(self._extract_keywords(chunk.page_content)),
                    "chunk_type": self._classify_chunk_content(chunk.page_content)
                })
            
            all_chunks.extend(chunks)
        
        logger.info(f"Creados {len(all_chunks)} chunks de {len(documents)} documentos")
        return all_chunks

    def _extract_keywords(self, content: str) -> List[str]:
        """
        Extrae keywords relevantes del contenido.
        
        Args:
            content: Contenido del chunk
            
        Returns:
            List[str]: Lista de keywords encontradas
        """
        content_lower = content.lower()
        found_keywords = [kw for kw in self.security_keywords if kw in content_lower]
        return found_keywords[:10]  # Limitar a las 10 más relevantes

    def _classify_chunk_content(self, content: str) -> str:
        """
        Clasifica el tipo de contenido del chunk.
        
        Args:
            content: Contenido del chunk
            
        Returns:
            str: Tipo de contenido
        """
        content_lower = content.lower()
        
        # Clasificación por contenido específico
        if any(word in content_lower for word in ["vulnerabilidad", "amenaza", "exploit"]):
            return "vulnerabilidades"
        elif any(word in content_lower for word in ["control", "salvaguarda", "mitigación"]):
            return "controles"
        elif any(word in content_lower for word in ["impacto", "daño", "consecuencia"]):
            return "impactos"
        elif any(word in content_lower for word in ["metodología", "framework", "proceso"]):
            return "metodologia"
        elif any(word in content_lower for word in ["iso", "nist", "magerit", "octave"]):
            return "marcos_referencia"
        else:
            return "conceptual"

    def get_document_stats(self, documents: List[Document]) -> Dict[str, Any]:
        """
        Obtiene estadísticas de los documentos cargados.
        
        Args:
            documents: Lista de documentos
            
        Returns:
            Dict: Estadísticas detalladas
        """
        if not documents:
            return {"total_documents": 0}
        
        # Calcular estadísticas
        total_chars = sum(len(doc.page_content) for doc in documents)
        doc_types = {}
        
        for doc in documents:
            doc_type = doc.metadata.get("document_type", "unknown")
            doc_types[doc_type] = doc_types.get(doc_type, 0) + 1
        
        return {
            "total_documents": len(documents),
            "total_characters": total_chars,
            "avg_document_length": total_chars // len(documents) if documents else 0,
            "document_types": doc_types,
            "languages": list(set(doc.metadata.get("language", "unknown") for doc in documents))
        }
