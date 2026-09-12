"""
Prompts para la evaluación semántica del modo de respuesta devuelto por la IA.
"""
import json
from typing import Any, Dict

PROMPT_SISTEMA_RESPUESTA = (
    "Eres un analizador técnico de protocolos y formatos de respuesta web especializado en APIs de Inteligencia Artificial.\n\n"
    "REGLAS ESTRICTAS:\n"
    "1. Evalúa el Content-Type, los encabezados y el fragmento del cuerpo de la respuesta proporcionados.\n"
    "2. Identifica si corresponde a Server-Sent Events (SSE), streaming por chunks, respuesta WebSocket, JSON directo u otro.\n"
    "3. Devuelve EXCLUSIVAMENTE un objeto JSON válido sin formato Markdown ni texto introductorio.\n"
    "4. La confianza debe ser un número flotante entre 0.0 y 1.0."
)


def construir_prompt_evaluacion_respuesta(respuesta_meta: Dict[str, Any]) -> str:
    """
    Construye el prompt de usuario para clasificar el tipo y comportamiento de la respuesta de la IA.

    Args:
        respuesta_meta: Metadatos de la respuesta (status, headers, muestra del body).

    Returns:
        String con el prompt formateado.
    """
    meta_serializada = json.dumps(respuesta_meta, ensure_ascii=False, indent=2)

    return (
        "Analiza la siguiente respuesta HTTP o evento de red para determinar el modo de entrega de la respuesta de IA:\n\n"
        f"METADATOS DE RESPUESTA:\n{meta_serializada}\n\n"
        "Debes responder con un objeto JSON con el siguiente formato exacto:\n"
        "{\n"
        '  "modo_respuesta": "<SSE | STREAMING_CHUNKED | WEBSOCKET | JSON_DIRECTO | DESCONOCIDO>",\n'
        '  "es_streaming": <true/false>,\n'
        '  "confianza": <float entre 0.0 y 1.0>,\n'
        '  "justificacion": "<breve justificación técnica en español>"\n'
        "}"
    )
