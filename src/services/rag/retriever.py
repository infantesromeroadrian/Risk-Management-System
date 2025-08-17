"""
Retriever Module para RAG System
Módulo especializado en recuperación y búsqueda semántica de documentos.
"""
from typing import List, Dict, Any, Optional
import asyncio
import logging

from langchain_community.vectorstores import Chroma
from langchain_core.retrievers import BaseRetriever
from langchain_core.documents import Document

from src.utils.logger import setup_logger

logger = setup_logger(__name__)


class SecurityRetriever:
    """
    Sistema de recuperación especializado para documentos de ciberseguridad.
    
    Características:
    - MMR (Maximal Marginal Relevance) para diversidad
    - Filtrado por metadata y tipos de documento
    - Scoring y ranking avanzado
    - Formateo optimizado para prompts
    """
    
    def __init__(self, vectorstore: Chroma):
        """
        Inicializa el sistema de retrieval.
        
        Args:
            vectorstore: Vector store configurado
        """
        self.vectorstore = vectorstore
        self.retriever = None
        self._search_stats = {
            "total_searches": 0,
            "avg_results_per_search": 0.0,
            "most_searched_terms": {}
        }
        
        logger.info("SecurityRetriever inicializado")

    def configure_retriever(
        self, 
        search_type: str = "mmr",
        k: int = 8,
        fetch_k: int = 16,
        lambda_mult: float = 0.7
    ) -> BaseRetriever:
        """
        Configura el retriever con parámetros optimizados.
        
        Args:
            search_type: Tipo de búsqueda (mmr, similarity, similarity_score_threshold)
            k: Número de documentos a recuperar
            fetch_k: Número de documentos a buscar inicialmente
            lambda_mult: Balance entre relevancia y diversidad (0=diversidad, 1=relevancia)
            
        Returns:
            BaseRetriever: Retriever configurado
        """
        try:
            if not self.vectorstore:
                raise ValueError("Vector store no disponible")
            
            # Configurar retriever con parámetros optimizados
            search_kwargs = {
                "k": k,
                "fetch_k": fetch_k,
                "lambda_mult": lambda_mult
            }
            
            self.retriever = self.vectorstore.as_retriever(
                search_type=search_type,
                search_kwargs=search_kwargs
            )
            
            logger.info(f"Retriever configurado: {search_type}, k={k}, fetch_k={fetch_k}")
            return self.retriever
            
        except Exception as e:
            logger.error(f"Error configurando retriever: {str(e)}")
            raise

    async def search_documents(
        self, 
        query: str, 
        max_results: int = 5,
        filter_metadata: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Busca documentos relevantes para una consulta.
        
        Args:
            query: Consulta de búsqueda
            max_results: Máximo número de resultados
            filter_metadata: Filtros opcionales por metadata
            
        Returns:
            List[Dict]: Lista de documentos con metadata enriquecida
        """
        try:
            if not self.retriever:
                raise ValueError("Retriever no configurado")
            
            # Ejecutar búsqueda de forma asíncrona
            relevant_docs = await asyncio.to_thread(
                self.retriever.invoke,
                query
            )
            
            # Aplicar filtros si se proporcionan
            if filter_metadata:
                relevant_docs = self._apply_metadata_filters(relevant_docs, filter_metadata)
            
            # Limitar resultados
            relevant_docs = relevant_docs[:max_results]
            
            # Formatear resultados con información enriquecida
            formatted_results = []
            for i, doc in enumerate(relevant_docs):
                result = {
                    "content": doc.page_content,
                    "metadata": doc.metadata,
                    "relevance_rank": i + 1,
                    "score": getattr(doc, "score", None),
                    "document_type": doc.metadata.get("document_type", "unknown"),
                    "filename": doc.metadata.get("filename", "unknown"),
                    "keywords": doc.metadata.get("keywords", []),
                    "chunk_info": {
                        "chunk_id": doc.metadata.get("chunk_id", ""),
                        "chunk_index": doc.metadata.get("chunk_index", 0),
                        "total_chunks": doc.metadata.get("total_chunks", 1)
                    }
                }
                formatted_results.append(result)
            
            # Actualizar estadísticas
            self._update_search_stats(query, len(formatted_results))
            
            logger.info(f"Búsqueda completada: '{query[:50]}...' -> {len(formatted_results)} resultados")
            return formatted_results
            
        except Exception as e:
            logger.error(f"Error en búsqueda: {str(e)}")
            return []

    def _apply_metadata_filters(self, documents: List[Document], filters: Dict[str, Any]) -> List[Document]:
        """
        Aplica filtros de metadata a los documentos.
        
        Args:
            documents: Lista de documentos a filtrar
            filters: Diccionario de filtros
            
        Returns:
            List[Document]: Documentos filtrados
        """
        filtered_docs = []
        
        for doc in documents:
            include_doc = True
            
            for filter_key, filter_value in filters.items():
                doc_value = doc.metadata.get(filter_key)
                
                if isinstance(filter_value, list):
                    # Filtro de lista (OR)
                    if doc_value not in filter_value:
                        include_doc = False
                        break
                else:
                    # Filtro exacto
                    if doc_value != filter_value:
                        include_doc = False
                        break
            
            if include_doc:
                filtered_docs.append(doc)
        
        return filtered_docs

    async def search_by_document_type(
        self, 
        query: str, 
        document_types: List[str],
        max_results: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Busca documentos filtrados por tipo.
        
        Args:
            query: Consulta de búsqueda
            document_types: Lista de tipos de documento permitidos
            max_results: Máximo número de resultados
            
        Returns:
            List[Dict]: Resultados filtrados por tipo
        """
        filter_metadata = {"document_type": document_types}
        return await self.search_documents(query, max_results, filter_metadata)

    async def search_by_keywords(
        self, 
        query: str, 
        required_keywords: List[str],
        max_results: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Busca documentos que contengan keywords específicos.
        
        Args:
            query: Consulta de búsqueda
            required_keywords: Keywords que deben estar presentes
            max_results: Máximo número de resultados
            
        Returns:
            List[Dict]: Resultados con keywords requeridos
        """
        try:
            # Realizar búsqueda inicial
            initial_results = await self.search_documents(query, max_results * 2)  # Buscar más para filtrar
            
            # Filtrar por keywords
            filtered_results = []
            for result in initial_results:
                doc_keywords = result.get("keywords", [])
                content_lower = result["content"].lower()
                
                # Verificar si contiene alguno de los keywords requeridos
                has_keywords = any(
                    keyword.lower() in doc_keywords or keyword.lower() in content_lower
                    for keyword in required_keywords
                )
                
                if has_keywords:
                    # Añadir información de keywords encontradas
                    result["matched_keywords"] = [
                        kw for kw in required_keywords 
                        if kw.lower() in content_lower or kw.lower() in doc_keywords
                    ]
                    filtered_results.append(result)
                
                if len(filtered_results) >= max_results:
                    break
            
            logger.info(f"Búsqueda por keywords: {len(filtered_results)} resultados con {required_keywords}")
            return filtered_results
            
        except Exception as e:
            logger.error(f"Error en búsqueda por keywords: {str(e)}")
            return []

    def format_context_for_prompt(self, search_results: List[Dict[str, Any]]) -> str:
        """
        Formatea los resultados de búsqueda para uso en prompts.
        
        Args:
            search_results: Resultados de búsqueda
            
        Returns:
            str: Contexto formateado para prompt
        """
        if not search_results:
            return ""
        
        formatted_lines = []
        formatted_lines.append("=== CONOCIMIENTO DE CIBERSEGURIDAD ===")
        
        for i, result in enumerate(search_results, 1):
            # Información de la fuente
            doc_type = result["metadata"].get("document_type", "").replace("_", " ").title()
            filename = result["metadata"].get("filename", "").replace(".txt", "")
            
            # Header de la fuente
            formatted_lines.append(f"\n--- Fuente {i}: {doc_type} ({filename}) ---")
            
            # Información adicional si está disponible
            keywords = result.get("keywords", [])
            if keywords:
                formatted_lines.append(f"Keywords: {', '.join(keywords[:5])}")
            
            # Contenido del chunk
            content = result["content"].strip()
            formatted_lines.append(content)
        
        formatted_lines.append("\n=== FIN DEL CONOCIMIENTO ===\n")
        
        return "\n".join(formatted_lines)

    def format_context_with_citations(self, search_results: List[Dict[str, Any]]) -> tuple[str, List[Dict[str, str]]]:
        """
        Formatea contexto con citas para trazabilidad.
        
        Args:
            search_results: Resultados de búsqueda
            
        Returns:
            tuple: (contexto_formateado, lista_de_citas)
        """
        if not search_results:
            return "", []
        
        formatted_lines = []
        citations = []
        
        formatted_lines.append("=== CONOCIMIENTO DE CIBERSEGURIDAD ===")
        
        for i, result in enumerate(search_results, 1):
            # Crear cita
            citation = {
                "id": f"ref_{i}",
                "source": result["metadata"].get("filename", "unknown"),
                "document_type": result["metadata"].get("document_type", "unknown"),
                "chunk_id": result["metadata"].get("chunk_id", ""),
                "relevance_rank": result.get("relevance_rank", i)
            }
            citations.append(citation)
            
            # Formatear contenido con referencia
            doc_type = citation["document_type"].replace("_", " ").title()
            filename = citation["source"].replace(".txt", "")
            
            formatted_lines.append(f"\n--- [{citation['id']}] {doc_type} ({filename}) ---")
            formatted_lines.append(result["content"].strip())
        
        formatted_lines.append("\n=== FIN DEL CONOCIMIENTO ===")
        formatted_lines.append("\nReferencias utilizadas:")
        for citation in citations:
            formatted_lines.append(f"[{citation['id']}] {citation['source']} - {citation['document_type']}")
        
        return "\n".join(formatted_lines), citations

    def _update_search_stats(self, query: str, results_count: int) -> None:
        """
        Actualiza estadísticas de búsqueda.
        
        Args:
            query: Consulta realizada
            results_count: Número de resultados obtenidos
        """
        self._search_stats["total_searches"] += 1
        
        # Actualizar promedio de resultados
        current_avg = self._search_stats["avg_results_per_search"]
        total_searches = self._search_stats["total_searches"]
        new_avg = ((current_avg * (total_searches - 1)) + results_count) / total_searches
        self._search_stats["avg_results_per_search"] = round(new_avg, 2)
        
        # Tracking de términos más buscados (simplificado)
        query_words = query.lower().split()
        for word in query_words:
            if len(word) > 3:  # Ignorar palabras muy cortas
                self._search_stats["most_searched_terms"][word] = \
                    self._search_stats["most_searched_terms"].get(word, 0) + 1

    def get_retriever_stats(self) -> Dict[str, Any]:
        """
        Obtiene estadísticas del sistema de retrieval.
        
        Returns:
            Dict: Estadísticas detalladas
        """
        # Top términos más buscados
        top_terms = sorted(
            self._search_stats["most_searched_terms"].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        return {
            "total_searches": self._search_stats["total_searches"],
            "avg_results_per_search": self._search_stats["avg_results_per_search"],
            "top_search_terms": dict(top_terms),
            "retriever_configured": self.retriever is not None,
            "vectorstore_available": self.vectorstore is not None
        }

    async def test_retrieval(self, test_queries: List[str] = None) -> Dict[str, Any]:
        """
        Ejecuta pruebas de retrieval con queries de ejemplo.
        
        Args:
            test_queries: Lista de consultas de prueba
            
        Returns:
            Dict: Resultados de las pruebas
        """
        if test_queries is None:
            test_queries = [
                "vulnerabilidad",
                "MAGERIT",
                "análisis de riesgo",
                "controles de seguridad",
                "principios de seguridad"
            ]
        
        test_results = {
            "queries_tested": len(test_queries),
            "successful_searches": 0,
            "failed_searches": 0,
            "total_results_found": 0,
            "details": []
        }
        
        for query in test_queries:
            try:
                results = await self.search_documents(query, max_results=3)
                test_results["successful_searches"] += 1
                test_results["total_results_found"] += len(results)
                
                test_results["details"].append({
                    "query": query,
                    "status": "success",
                    "results_count": len(results),
                    "top_result": results[0]["filename"] if results else None
                })
                
            except Exception as e:
                test_results["failed_searches"] += 1
                test_results["details"].append({
                    "query": query,
                    "status": "failed",
                    "error": str(e)
                })
        
        return test_results
