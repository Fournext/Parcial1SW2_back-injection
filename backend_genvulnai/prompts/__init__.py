"""
Módulo de plantillas de prompts centralizadas para el análisis semántico con Ollama.
"""
from backend_genvulnai.prompts.seleccionar_interfaz import (
    PROMPT_SISTEMA_INTERFAZ,
    construir_prompt_interfaz,
)
from backend_genvulnai.prompts.seleccionar_canal import (
    PROMPT_SISTEMA_CANAL,
    construir_prompt_canal,
)
from backend_genvulnai.prompts.evaluar_respuesta import (
    PROMPT_SISTEMA_RESPUESTA,
    construir_prompt_evaluacion_respuesta,
)

__all__ = [
    'PROMPT_SISTEMA_INTERFAZ',
    'construir_prompt_interfaz',
    'PROMPT_SISTEMA_CANAL',
    'construir_prompt_canal',
    'PROMPT_SISTEMA_RESPUESTA',
    'construir_prompt_evaluacion_respuesta',
]
