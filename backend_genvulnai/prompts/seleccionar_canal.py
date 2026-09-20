"""
Prompts para la selección y desambiguación semántica del canal de red principal (HTTP / WebSocket) hacia la IA.
"""
import json
from typing import Any, Dict, List

PROMPT_SISTEMA_CANAL = (
    "Eres un analizador técnico de tráfico de red especializado en identificar peticiones HTTP y tramas WebSocket "
    "que transmiten prompts o mensajes dirigidos a modelos de Inteligencia Artificial.\n\n"
    "REGLAS ESTRICTAS:\n"
    "1. Basa tu análisis ÚNICAMENTE en las observaciones de red proporcionadas.\n"
    "2. NO inventes endpoints, parámetros ni cuerpos que no aparezcan en la entrada.\n"
    "3. Considera la presencia de marcadores de prueba, endpoints con nombres de IA/chat, estructuras JSON de prompts y métodos POST.\n"
    "4. REGLA CRÍTICA DE EXCLUSIÓN: NUNCA selecciones peticiones de inicio de sesión, autenticación, registro o tokens "
    "(por ejemplo endpoints como /login, /signin, /auth, /token, /oauth o peticiones cuyos cuerpos sean credenciales como correo, email, password, usuario). "
    "Los endpoints de autenticación NO son canales de IA bajo ninguna circunstancia.\n"
    "5. Si ninguna petición corresponde claramente a un canal de IA, marca 'indice_seleccionado': null y 'evidencia_insuficiente': true.\n"
    "6. Devuelve EXCLUSIVAMENTE un objeto JSON válido, sin texto adicional, sin bloques de código Markdown, sin comentarios.\n"
    "7. La confianza debe ser un número flotante entre 0.0 y 1.0."
)


def construir_prompt_canal(observaciones: List[Dict[str, Any]], marcador: str) -> str:
    """
    Construye el prompt de usuario con las observaciones de red y el marcador enviado.

    Args:
        observaciones: Lista de peticiones o mensajes candidatos sanitizados.
        marcador: Marcador único que fue inyectado durante la prueba de entrada.

    Returns:
        String con el prompt formateado.
    """
    observaciones_serializadas = json.dumps(observaciones, ensure_ascii=False, indent=2)

    return (
        f"Se inyectó el siguiente texto de prueba (marcador): '{marcador}'.\n\n"
        f"A continuación se presentan las observaciones de red capturadas durante la interacción:\n"
        f"OBSERVACIONES:\n{observaciones_serializadas}\n\n"
        "Determina cuál de estas observaciones representa el canal principal de envío hacia la IA.\n"
        "Debes responder con un objeto JSON con el siguiente formato exacto:\n"
        "{\n"
        '  "indice_seleccionado": <entero o null>,\n'
        '  "confianza": <float entre 0.0 y 1.0>,\n'
        '  "campo_prompt": "<nombre del campo que contiene el prompt o null>",\n'
        '  "modo_entrada": "<JSON | FORM | TEXTO_PLANO | DESCONOCIDO>",\n'
        '  "modo_respuesta": "<SSE | STREAMING_CHUNKED | WEBSOCKET | JSON_DIRECTO | DESCONOCIDO>",\n'
        '  "justificacion": "<breve explicación técnica en español>",\n'
        '  "evidencia_insuficiente": <true/false>\n'
        "}"
    )
