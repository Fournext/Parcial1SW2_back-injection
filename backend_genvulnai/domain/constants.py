"""
Constantes del dominio, heurísticas y patrones de seguridad.
"""
from typing import List

# Palabras clave heurísticas para detectar elementos de entrada y envío de IA
PALABRAS_CLAVE_IA: List[str] = [
    # Español
    'chat', 'mensaje', 'pregunta', 'escribe', 'enviar', 'consultar', 'ia', 'asistente',
    'prompt', 'consulta', 'preguntar', 'comenzar', 'texto', 'generar', 'modelo',
    # Inglés
    'ask', 'question', 'message', 'prompt', 'write', 'type', 'send', 'submit',
    'ai', 'assistant', 'query', 'generate', 'input', 'conversation', 'talk'
]

# Palabras clave para endpoints sospechosos de procesar IA
PALABRAS_CLAVE_ENDPOINT: List[str] = [
    'chat', 'completion', 'completions', 'message', 'messages', 'inference',
    'generate', 'conversation', 'assistant', 'ai', 'predict', 'stream',
    'llm', 'query', 'agent', 'v1/chat', 'openai', 'anthropic', 'gemini'
]

# Encabezados sensibles que deben ser sanitizados obligatoriamente
HEADERS_SENSIBLES: List[str] = [
    'authorization',
    'cookie',
    'set-cookie',
    'x-api-key',
    'api-key',
    'x-csrf-token',
    'x-csrftoken',
    'proxy-authorization',
    'token',
    'x-auth-token'
]

# Prefijo para generar identificadores de prueba únicos
PREFIJO_MARCADOR: str = "DISCOVERY_TEST_"

# Esquemas de red permitidos exclusivamente
ESQUEMAS_PERMITIDOS: List[str] = ['http', 'https']

# Límite por defecto de almacenamiento de cuerpo de petición (en bytes)
LIMITE_BODY_BYTES_DEFAULT: int = 51200

# Ponderaciones y umbrales para resolución semántica con IA (Ollama)
PESO_HEURISTICA: float = 0.65
PESO_IA: float = 0.35
UMBRAL_DIFERENCIA_CANDIDATOS: float = 0.15

# Configuración del Explorador Activo del DOM
MAX_PASOS_EXPLORACION: int = 25           # Máximo de interacciones antes de detenerse
MAX_PROFUNDIDAD_NAVEGACION: int = 3       # Niveles de profundidad en navegación interna
TIEMPO_ESPERA_TRAS_CLICK_MS: int = 2000   # ms para esperar renderizado tras cada click
MAX_ELEMENTOS_POR_PAGINA: int = 50        # Límite de elementos interactivos a evaluar por vista

# Selectores CSS para elementos interactivos explorables
SELECTORES_EXPLORABLES: List[str] = [
    'button:not([disabled])',
    'a[href]:not([href^="http://"]):not([href^="https://"]):not([href^="mailto:"]):not([href^="tel:"])',
    'a[href*="chat" i]',
    'a[href*="asistente" i]',
    'a[href*="assistant" i]',
    'a[href*="ai" i]',
    '[role="tab"]',
    '[role="menuitem"]',
    '.floating-button',
    '[class*="float" i][class*="btn" i]',
    '[class*="widget" i]',
    '[class*="chat" i]:not(input):not(textarea)',
    '[id*="chat" i]:not(input):not(textarea)',
    '[aria-label*="chat" i]',
    '[aria-label*="asistente" i]',
    '[aria-label*="assistant" i]',
]

# Palabras clave para priorizar elementos explorables
PALABRAS_CLAVE_EXPLORACION: List[str] = [
    'chat', 'asistente', 'assistant', 'ai', 'ia', 'bot', 'help', 'ayuda',
    'soporte', 'support', 'pregunta', 'ask', 'conversar', 'talk',
    'abrir', 'open', 'iniciar', 'start', 'nuevo', 'new',
    'generar', 'generate', 'modelo', 'analizar', 'prompt',
]

# Eventos para logs estructurados
class EventosLog:
    SCAN_STARTED = "SCAN_STARTED"
    PAGE_LOADED = "PAGE_LOADED"
    AI_INPUT_FOUND = "AI_INPUT_FOUND"
    MARKER_SENT = "MARKER_SENT"
    REQUEST_MATCHED = "REQUEST_MATCHED"
    WEBSOCKET_MATCHED = "WEBSOCKET_MATCHED"
    AUTH_DETECTED = "AUTH_DETECTED"
    SCAN_FINISHED = "SCAN_FINISHED"
    SCAN_FAILED = "SCAN_FAILED"
    
    # Eventos de integración con Ollama (IA Local)
    OLLAMA_CALL_STARTED = "OLLAMA_CALL_STARTED"
    OLLAMA_CALL_SUCCESS = "OLLAMA_CALL_SUCCESS"
    OLLAMA_CALL_FAILED = "OLLAMA_CALL_FAILED"
    OLLAMA_FALLBACK_TRIGGERED = "OLLAMA_FALLBACK_TRIGGERED"
    OLLAMA_JSON_PARSE_ERROR = "OLLAMA_JSON_PARSE_ERROR"
    OLLAMA_SKIPPED_HIGH_CONFIDENCE = "OLLAMA_SKIPPED_HIGH_CONFIDENCE"
    OLLAMA_SKIPPED_DISABLED = "OLLAMA_SKIPPED_DISABLED"
    OLLAMA_COMBINED_SCORE = "OLLAMA_COMBINED_SCORE"

    # Eventos del explorador activo del DOM
    EXPLORER_STARTED = "EXPLORER_STARTED"
    EXPLORER_CLICK = "EXPLORER_CLICK"
    EXPLORER_NAVIGATION = "EXPLORER_NAVIGATION"
    EXPLORER_STATE_CHANGE = "EXPLORER_STATE_CHANGE"
    EXPLORER_INTERFACE_FOUND = "EXPLORER_INTERFACE_FOUND"
    EXPLORER_MAX_STEPS = "EXPLORER_MAX_STEPS"
    EXPLORER_FINISHED = "EXPLORER_FINISHED"
    EXPLORER_LOOP_DETECTED = "EXPLORER_LOOP_DETECTED"

    # Eventos de sondeo y verificación de inputs
    PROBE_INPUT_STARTED = "PROBE_INPUT_STARTED"
    PROBE_INPUT_CONFIRMED = "PROBE_INPUT_CONFIRMED"
    PROBE_INPUT_FAILED = "PROBE_INPUT_FAILED"

    # Eventos de la sesión de ataque
    ATTACK_SESSION_STARTED = "ATTACK_SESSION_STARTED"
    ATTACK_TURN_STARTED = "ATTACK_TURN_STARTED"
    ATTACK_PROMPT_GENERATED = "ATTACK_PROMPT_GENERATED"
    ATTACK_SENT_TO_D1 = "ATTACK_SENT_TO_D1"
    ATTACK_D1_RESPONSE = "ATTACK_D1_RESPONSE"
    ATTACK_JUDGE_EVALUATION = "ATTACK_JUDGE_EVALUATION"
    ATTACK_RESET_TRIGGERED = "ATTACK_RESET_TRIGGERED"
    ATTACK_SUCCESS = "ATTACK_SUCCESS"
    ATTACK_MAX_TURNS = "ATTACK_MAX_TURNS"
    ATTACK_ERROR = "ATTACK_ERROR"
    ATTACK_SESSION_FINISHED = "ATTACK_SESSION_FINISHED"

# Puntuación mínima para considerar un input como "probablemente de IA"
# Un input genérico (sin keywords) tiene score=1.0; un textarea con 1 keyword tiene score=6.0
PUNTUACION_MINIMA_INPUT_CONFIABLE: float = 3.0

# Constantes del orquestador de ataque
MAX_TURNOS_ATAQUE_DEFAULT: int = 20
MAX_FRACASOS_CONSECUTIVOS_RESET: int = 3
PUNTAJE_EXITO: int = 10
TEMPERATURA_A1: float = 0.7
TEMPERATURA_J1: float = 0.1
MODELO_J1_DEFAULT: str = "hf.co/unsloth/Qwen3.5-4B-GGUF:UD-Q4_K_XL"

