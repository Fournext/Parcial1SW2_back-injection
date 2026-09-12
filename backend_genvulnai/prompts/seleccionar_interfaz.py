"""
Prompts para la selección y desambiguación semántica de elementos de interfaz de usuario para interacción con IA.
"""
import json
from typing import Any, Dict, List

PROMPT_SISTEMA_INTERFAZ = (
    "Eres un analizador técnico de interfaces web especializado en identificar controles de entrada "
    "destinados a interactuar con modelos de Inteligencia Artificial (chatbots, asistentes, prompts).\n\n"
    "REGLAS ESTRICTAS:\n"
    "1. Basa tu análisis ÚNICAMENTE en la información proporcionada en la lista de candidatos.\n"
    "2. NO inventes etiquetas, clases, selectores ni atributos que no estén en la entrada.\n"
    "3. Si ningún elemento parece ser un campo de entrada para IA con suficiente certeza, marca 'evidencia_insuficiente': true.\n"
    "4. Devuelve EXCLUSIVAMENTE un objeto JSON válido, sin texto adicional, sin bloques de código Markdown, sin explicaciones fuera del JSON.\n"
    "5. La confianza debe ser un número flotante entre 0.0 y 1.0."
)


def construir_prompt_interfaz(candidatos: List[Dict[str, Any]]) -> str:
    """
    Construye el prompt de usuario con la lista de candidatos a evaluar.

    Args:
        candidatos: Lista de diccionarios representando los elementos candidatos y sus atributos.

    Returns:
        String con el prompt formateado.
    """
    candidatos_serializados = json.dumps(candidatos, ensure_ascii=False, indent=2)

    return (
        "Analiza los siguientes elementos candidatos de una página web y determina cuál de ellos "
        "corresponde al campo principal de entrada de mensajes para la Inteligencia Artificial.\n\n"
        f"CANDIDATOS:\n{candidatos_serializados}\n\n"
        "Debes responder con un objeto JSON con el siguiente formato exacto:\n"
        "{\n"
        '  "indice_seleccionado": <entero o null>,\n'
        '  "confianza": <float entre 0.0 y 1.0>,\n'
        '  "justificacion": "<breve explicación técnica en español>",\n'
        '  "evidencia_insuficiente": <true/false>\n'
        "}"
    )
