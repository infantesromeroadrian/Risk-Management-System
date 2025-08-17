console.log('🚀 main.js cargado - versión con debugging');

document.addEventListener('DOMContentLoaded', () => {
    console.log('📄 DOM listo - inicializando aplicación');
    const form = document.getElementById('analysis-form');
    const titleInput = document.getElementById('incident-title');
    const descriptionTextarea = document.getElementById('incident-description');
    const exampleButtons = document.querySelectorAll('.example-btn');

    // Cargar ejemplos de incidentes  
    let incidentExamples = {};

    // Función para cargar los ejemplos
    async function loadExamples() {
        try {
            const response = await fetch('/api/examples');
            const result = await response.json();
            
            if (result.status === 'success' && result.data) {
                incidentExamples = result.data; // Estructura con categorías
            }
        } catch (error) {
            console.error('Error cargando ejemplos:', error);
        }
    }

    // Cargar ejemplos al iniciar
    loadExamples();

    // Manejar clic en botones de ejemplo - mostrar submenu
    exampleButtons.forEach(button => {
        button.addEventListener('click', async () => {
            // Ocultar otros submenús
            document.querySelectorAll('.subexample-item').forEach(item => {
                item.remove();
            });

            const category = button.dataset.category;
            if (incidentExamples[category] && incidentExamples[category].ejemplos) {
                const examples = incidentExamples[category].ejemplos;
                
                // Crear elementos de ejemplo dinámicamente
                const container = document.getElementById(`subexamples-${category}`);
                container.innerHTML = '';
                
                examples.forEach(example => {
                    const div = document.createElement('div');
                    div.className = 'subexample-item';
                    div.innerHTML = `
                        <h4>${example.titulo}</h4>
                        <p>${example.descripcion}</p>
                        ${example.analisis_recomendado ? `<small>Análisis recomendado: ${example.analisis_recomendado}</small>` : ''}
                    `;
                    
                    div.addEventListener('click', () => {
                        titleInput.value = example.titulo;
                        descriptionTextarea.value = example.descripcion;
                        
                        // Ocultar submenús después de seleccionar
                        document.querySelectorAll('.subexamples-list').forEach(list => {
                            list.classList.remove('active');
                        });
                    });
                    
                    container.appendChild(div);
                });
                
                container.classList.add('active');
            }
        });
    });

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const title = titleInput.value.trim();
        const description = descriptionTextarea.value.trim();
        
        if (!title || !description) {
            alert('Por favor, complete todos los campos');
            return;
        }

        // Mostrar barra de progreso
        console.log('🚀 Iniciando análisis - mostrando barra progreso');
        showProgressBar();

        try {
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    titulo: title,
                    descripcion: description
                })
            });

            const data = await response.json();
            
            if (data.status === 'success') {
                // Completar progreso antes de mostrar resultados
                completeProgress();
                setTimeout(() => {
                    hideProgressBar();
                    displayResults(data.data);
                }, 1000);
            } else {
                hideProgressBar();
                throw new Error('Error en el análisis');
            }
        } catch (error) {
            hideProgressBar();
            console.error('Error:', error);
            alert('Ocurrió un error al analizar el incidente');
        }
    });

    function displayResults(results) {
        // Mostrar vulnerabilidades
        const vulnerabilitiesContent = document.getElementById('vulnerabilities-list');
        if (vulnerabilitiesContent && results.vulnerabilities) {
            vulnerabilitiesContent.innerHTML = formatVulnerabilities(results.vulnerabilities);
        }

        // Mostrar impactos
        const impactsContent = document.getElementById('impacts-list');
        if (impactsContent && results.impacts) {
            impactsContent.innerHTML = formatImpacts(results.impacts);
        }

        // Mostrar controles
        const controlsContent = document.getElementById('controls-list');
        if (controlsContent && results.controls) {
            controlsContent.innerHTML = formatControls(results.controls);
        }

        // Mostrar la sección de resultados
        const resultSection = document.getElementById('result-section');
        if (resultSection) {
            resultSection.style.display = 'block';
            resultSection.scrollIntoView({ behavior: 'smooth' });
        }
    }

    function formatVulnerabilities(vulnerabilities) {
        return vulnerabilities.map(v => `
            <div class="vulnerability-item">
                <h4>Tipo: ${v.type}</h4>
                <p><strong>Descripción:</strong> ${v.description}</p>
                <p><strong>Severidad:</strong> ${v.severity}</p>
                <p><strong>Categoría:</strong> ${v.category}</p>
                <p><strong>Recomendación:</strong> ${v.recommendation}</p>
                ${v.cve_ids && v.cve_ids.length ? `<p><strong>CVE IDs:</strong> ${v.cve_ids.join(', ')}</p>` : ''}
                ${v.mitre_attack_ids && v.mitre_attack_ids.length ? `<p><strong>MITRE ATT&CK:</strong> ${v.mitre_attack_ids.join(', ')}</p>` : ''}
            </div>
        `).join('');
    }

    function formatImpacts(impacts) {
        return impacts.map(i => `
            <div class="impact-item">
                <h4>Tipo: ${i.type}</h4>
                <p><strong>Descripción:</strong> ${i.description}</p>
                <p><strong>Impacto:</strong> ${i.impact_level}</p>
                <p><strong>Recuperable:</strong> ${i.recoverable ? 'Sí' : 'No'}</p>
                <p><strong>Tiempo de Recuperación:</strong> ${i.recovery_time}</p>
                ${i.probability ? `<p><strong>Probabilidad:</strong> ${i.probability}</p>` : ''}
                ${i.risk_value ? `<p><strong>Valor de Riesgo:</strong> ${i.risk_value}</p>` : ''}
            </div>
        `).join('');
    }

    function formatControls(controls) {
        return controls.map(c => `
            <div class="control-item">
                <h4>Tipo: ${c.type}</h4>
                <p><strong>Descripción:</strong> ${c.description}</p>
                <p><strong>Prioridad:</strong> ${c.priority}</p>
                <p><strong>Costo Estimado:</strong> ${c.estimated_cost}</p>
                <p><strong>Tiempo de Implementación:</strong> ${c.implementation_time}</p>
                ${c.reference_frameworks && c.reference_frameworks.length ? `<p><strong>Marcos de Referencia:</strong> ${c.reference_frameworks.join(', ')}</p>` : ''}
                ${c.kpis && c.kpis.length ? `<p><strong>KPIs:</strong> ${c.kpis.join(', ')}</p>` : ''}
            </div>
        `).join('');
    }

    // ========================================================================
    // FUNCIONES DE BARRA DE PROGRESO
    // ========================================================================
    
    let progressInterval = null;
    let currentProgress = 0;
    
    const progressSteps = [
        { percent: 0, message: "Preparando análisis...", step: null },
        { percent: 15, message: "Inicializando sistema RAG...", step: "step-rag" },
        { percent: 35, message: "Cargando documentos de ciberseguridad...", step: "step-rag" },
        { percent: 50, message: "Buscando contexto relevante...", step: "step-context" },
        { percent: 65, message: "Contexto obtenido, consultando GPT-4.1...", step: "step-context" },
        { percent: 75, message: "Analizando vulnerabilidades...", step: "step-analysis" },
        { percent: 85, message: "Evaluando impactos potenciales...", step: "step-analysis" },
        { percent: 95, message: "Generando recomendaciones...", step: "step-analysis" },
        { percent: 100, message: "¡Análisis completado exitosamente!", step: "step-results" }
    ];
    
    function showProgressBar() {
        console.log('📊 showProgressBar() llamada');
        
        const overlay = document.getElementById('progress-overlay');
        const progressBar = document.getElementById('progress-bar');
        const progressPercentage = document.getElementById('progress-percentage');
        const progressMessage = document.getElementById('progress-message');
        
        // Debug: verificar elementos
        console.log('🔍 Elementos encontrados:', {
            overlay: !!overlay,
            progressBar: !!progressBar,
            progressPercentage: !!progressPercentage,
            progressMessage: !!progressMessage
        });
        
        if (!overlay) {
            console.error('❌ No se encontró progress-overlay');
            return;
        }
        
        // Reset progress
        currentProgress = 0;
        if (progressBar) progressBar.style.width = '0%';
        if (progressPercentage) progressPercentage.textContent = '0%';
        if (progressMessage) progressMessage.textContent = 'Preparando análisis...';
        
        // Reset steps
        document.querySelectorAll('.progress-step').forEach(step => {
            step.classList.remove('active', 'completed');
        });
        
        // Show overlay
        console.log('✅ Mostrando overlay');
        overlay.classList.add('active');
        
        // Start progress simulation
        startProgressSimulation();
    }
    
    function hideProgressBar() {
        const overlay = document.getElementById('progress-overlay');
        overlay.classList.remove('active');
        
        // Clear interval
        if (progressInterval) {
            clearInterval(progressInterval);
            progressInterval = null;
        }
    }
    
    function startProgressSimulation() {
        let stepIndex = 0;
        
        progressInterval = setInterval(() => {
            // Increment progress gradually
            if (currentProgress < 95) {
                currentProgress += Math.random() * 3; // Random increment
                
                // Check if we should move to next step
                while (stepIndex < progressSteps.length - 1 && 
                       currentProgress >= progressSteps[stepIndex + 1].percent) {
                    stepIndex++;
                    updateProgressStep(progressSteps[stepIndex]);
                }
                
                updateProgressBar(Math.min(currentProgress, 95));
            }
        }, 500); // Update every 500ms
    }
    
    function updateProgressBar(percent) {
        const progressBar = document.getElementById('progress-bar');
        const progressPercentage = document.getElementById('progress-percentage');
        
        progressBar.style.width = `${percent}%`;
        progressPercentage.textContent = `${Math.round(percent)}%`;
    }
    
    function updateProgressStep(step) {
        const progressMessage = document.getElementById('progress-message');
        
        // Update message
        progressMessage.textContent = step.message;
        
        // Update step visual state
        if (step.step) {
            // Mark previous steps as completed
            document.querySelectorAll('.progress-step').forEach(stepEl => {
                stepEl.classList.remove('active');
                if (stepEl.id !== step.step) {
                    const stepNum = parseInt(stepEl.id.split('-')[1] === 'rag' ? '1' : 
                                           stepEl.id.split('-')[1] === 'context' ? '2' : 
                                           stepEl.id.split('-')[1] === 'analysis' ? '3' : '4');
                    const currentStepNum = parseInt(step.step.split('-')[1] === 'rag' ? '1' : 
                                                  step.step.split('-')[1] === 'context' ? '2' : 
                                                  step.step.split('-')[1] === 'analysis' ? '3' : '4');
                    
                    if (stepNum < currentStepNum) {
                        stepEl.classList.add('completed');
                    }
                }
            });
            
            // Mark current step as active
            const currentStepEl = document.getElementById(step.step);
            if (currentStepEl) {
                currentStepEl.classList.add('active');
            }
        }
    }
    
    function completeProgress() {
        if (progressInterval) {
            clearInterval(progressInterval);
            progressInterval = null;
        }
        
        // Complete all steps
        document.querySelectorAll('.progress-step').forEach(step => {
            step.classList.remove('active');
            step.classList.add('completed');
        });
        
        // Set to 100%
        updateProgressBar(100);
        document.getElementById('progress-message').textContent = 
            '¡Análisis completado exitosamente!';
    }
    
    // ========================================================================
    // FUNCIÓN DE TEST PARA DEBUG
    // ========================================================================
    
    // Hacer función disponible globalmente para testing
    window.testProgressBar = function() {
        console.log('🧪 Test manual de barra de progreso');
        showProgressBar();
        
        // Auto-cerrar después de 3 segundos
        setTimeout(() => {
            console.log('🧪 Test completado - cerrando barra');
            hideProgressBar();
        }, 3000);
    };
    
    console.log('✅ Aplicación inicializada - usar window.testProgressBar() para probar');
}); 