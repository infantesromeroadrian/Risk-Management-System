#!/usr/bin/env python3
"""
Script de prueba para verificar el sistema RAG de Risk-Guardian
"""
import asyncio
import sys
import os
from pathlib import Path

# Añadir src al path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.services.rag import (
    SecurityKnowledgeRAG, 
    search_security_knowledge,
    get_rag_service,
    get_rag_health,
    get_rag_stats,
    test_rag_system
)


async def test_modular_rag_system():
    """Prueba el sistema RAG modularizado."""
    print("🚀 Probando Sistema RAG Modularizado")
    print("="*50)
    
    try:
        # 1. Test usando función singleton
        print("1. Inicializando servicio RAG (singleton)...")
        rag_service = await get_rag_service()
        print("✅ Servicio RAG inicializado usando singleton")
        
        # 2. Health check
        print("\n2. Verificando salud del sistema...")
        health = await get_rag_health()
        print(f"   - Estado: {health['status']}")
        if health['status'] == 'healthy':
            print("✅ Sistema RAG saludable")
        else:
            print("⚠️ Sistema RAG con problemas")
        
        # 3. Estadísticas del sistema
        print("\n3. Estadísticas del sistema:")
        stats = await get_rag_stats()
        print(f"   - Documentos cargados: {stats.get('documents_loaded', 0)}")
        print(f"   - Chunks creados: {stats.get('chunks_created', 0)}")
        print(f"   - Tiempo de inicialización: {stats.get('initialization_time', 'N/A')}s")
        print(f"   - Llamadas de retrieval: {stats.get('retrieval_calls', 0)}")
        
        # 4. Pruebas automáticas integradas
        print("\n4. Ejecutando pruebas automáticas...")
        auto_test_results = await test_rag_system()
        
        if auto_test_results.get('error'):
            print(f"   ❌ Error en pruebas automáticas: {auto_test_results['error']}")
        else:
            successful = auto_test_results.get('successful_searches', 0)
            total = auto_test_results.get('queries_tested', 0)
            print(f"   ✅ Pruebas automáticas: {successful}/{total} exitosas")
        
        # 5. Pruebas de funciones específicas
        print("\n5. Pruebas de funciones específicas:")
        
        # 5.1 Búsqueda general
        print("\n   5.1. Búsqueda general...")
        results = await search_security_knowledge("vulnerabilidades", 3)
        if results:
            print(f"   ✅ Búsqueda general: {len(results)} resultados")
        else:
            print("   ⚠️ No se encontraron resultados en búsqueda general")
        
        # 5.2 Búsqueda por metodología
        print("\n   5.2. Búsqueda por metodología...")
        from src.services.rag import search_by_methodology
        magerit_results = await search_by_methodology("análisis de riesgo", "MAGERIT", 2)
        if magerit_results:
            print(f"   ✅ Búsqueda MAGERIT: {len(magerit_results)} resultados")
        else:
            print("   ⚠️ No se encontraron resultados para MAGERIT")
        
        # 6. Prueba de formateo
        print("\n6. Prueba de formateo de contexto:")
        if results:
            from src.services.rag import format_context_for_prompt
            formatted = format_context_for_prompt(results[:2])
            if formatted:
                print(f"   ✅ Contexto formateado ({len(formatted)} caracteres)")
                print(f"   Preview: {formatted[:150]}...")
            else:
                print("   ⚠️ Error en formateo de contexto")
        
        print("\n🎉 Pruebas del sistema modularizado completadas!")
        
    except Exception as e:
        print(f"\n❌ Error en pruebas modularizadas: {str(e)}")
        import traceback
        traceback.print_exc()


async def test_individual_modules():
    """Prueba módulos individuales del sistema RAG."""
    print("\n" + "="*50)
    print("🔧 Pruebas de Módulos Individuales")
    print("="*50)
    
    try:
        from src.services.rag.document_loader import SecurityDocumentLoader
        from src.services.rag.vector_store import SecurityVectorStore
        
        # Test Document Loader
        print("\n1. Probando SecurityDocumentLoader...")
        loader = SecurityDocumentLoader("docs")
        
        try:
            documents = await loader.load_all_documents()
            if documents:
                print(f"   ✅ Cargados {len(documents)} documentos")
                
                # Test de estadísticas
                stats = loader.get_document_stats(documents)
                print(f"   📊 Estadísticas: {stats['total_documents']} docs, "
                      f"{stats['total_characters']} chars")
                
                # Test de splitting
                chunks = await loader.split_documents(documents[:1])  # Solo el primer doc
                if chunks:
                    print(f"   ✅ Creados {len(chunks)} chunks del primer documento")
                else:
                    print("   ⚠️ No se crearon chunks")
            else:
                print("   ❌ No se cargaron documentos")
        except Exception as e:
            print(f"   ❌ Error en DocumentLoader: {str(e)}")
        
        # Test Vector Store (solo inicialización, sin embeddings reales)
        print("\n2. Probando SecurityVectorStore...")
        try:
            vector_store = SecurityVectorStore("test_vectorstore")
            stats = vector_store.get_vectorstore_stats()
            print(f"   ✅ VectorStore inicializado - Estado: {stats['status']}")
            
            # Verificar cache
            cache_exists = vector_store._cache_exists()
            print(f"   📁 Cache existente: {cache_exists}")
        except Exception as e:
            print(f"   ❌ Error en VectorStore: {str(e)}")
        
        print("\n🔧 Pruebas de módulos individuales completadas")
        
    except Exception as e:
        print(f"\n❌ Error en pruebas de módulos: {str(e)}")
        import traceback
        traceback.print_exc()


async def test_specific_searches():
    """Prueba búsquedas específicas de ciberseguridad."""
    print("\n" + "="*50)
    print("🔍 Pruebas de Búsquedas Específicas")
    print("="*50)
    
    cybersecurity_queries = [
        {
            "query": "¿Qué es una vulnerabilidad según MAGERIT?",
            "expected_docs": ["medicion_riesgo"]
        },
        {
            "query": "Principios de confidencialidad, integridad y disponibilidad",
            "expected_docs": ["principios_seguridad"]
        },
        {
            "query": "Gestión de riesgos ISO 31000",
            "expected_docs": ["riesgos_ti"]
        },
        {
            "query": "Controles preventivos detectivos correctivos",
            "expected_docs": ["principios_seguridad"]
        },
        {
            "query": "Metodología OCTAVE para análisis de amenazas",
            "expected_docs": ["medicion_riesgo"]
        }
    ]
    
    for i, test_case in enumerate(cybersecurity_queries, 1):
        query = test_case["query"]
        expected_docs = test_case["expected_docs"]
        
        print(f"\n{i}. Query: '{query}'")
        print(f"   Documentos esperados: {expected_docs}")
        
        try:
            results = await search_security_knowledge(query, 3)
            
            if results:
                print(f"   ✅ Encontrados {len(results)} resultados")
                found_docs = [r['metadata'].get('filename', '').replace('.txt', '') 
                             for r in results]
                
                # Verificar si algún documento esperado está en los resultados
                matches = [doc for doc in expected_docs if any(doc in found for found in found_docs)]
                if matches:
                    print(f"   ✅ Documentos coincidentes: {matches}")
                else:
                    print(f"   ⚠️ No se encontraron documentos esperados")
                    print(f"   Documentos encontrados: {found_docs}")
            else:
                print("   ❌ No se encontraron resultados")
                
        except Exception as e:
            print(f"   ❌ Error en búsqueda: {str(e)}")


async def main():
    """Función principal."""
    print("Risk-Guardian RAG System Test")
    print("Verificando sistema de Retrieval-Augmented Generation")
    
    # Verificar que existe la carpeta docs
    docs_path = Path("docs")
    if not docs_path.exists():
        print(f"❌ Error: No existe la carpeta 'docs' en {docs_path.absolute()}")
        print("   Asegúrate de ejecutar este script desde la raíz del proyecto")
        return
    
    # Verificar archivos de documentación
    doc_files = list(docs_path.glob("*.txt"))
    if not doc_files:
        print(f"❌ Error: No hay archivos .txt en la carpeta docs")
        return
        
    print(f"✅ Carpeta docs encontrada con {len(doc_files)} archivos:")
    for doc_file in doc_files:
        print(f"   - {doc_file.name}")
    
    # Ejecutar pruebas
    await test_modular_rag_system()
    await test_individual_modules()
    await test_specific_searches()
    
    print("\n" + "="*50)
    print("🏁 Pruebas completadas")
    print("="*50)


if __name__ == "__main__":
    # Verificar que tenemos la API key
    if not os.getenv("OPENAI_API_KEY"):
        print("⚠️ Warning: OPENAI_API_KEY no está configurada")
        print("   Algunas pruebas pueden fallar")
    
    asyncio.run(main())
