"""
Enumeraciones de dominio para el descubrimiento y análisis de canales de IA.
"""
from django.db import models


class EstadoEscaneo(models.TextChoices):
    """Estados del ciclo de vida del escaneo de descubrimiento."""
    PENDIENTE = 'pendiente', 'Pendiente'
    EN_PROGRESO = 'en_progreso', 'En Progreso'
    COMPLETADO = 'completado', 'Completado'
    FALLIDO = 'fallido', 'Fallido'


class Protocolo(models.TextChoices):
    """Protocolos de red identificables."""
    HTTP = 'http', 'HTTP'
    HTTPS = 'https', 'HTTPS'
    WS = 'ws', 'WebSocket'
    WSS = 'wss', 'WebSocket Secure'


class MetodoHTTP(models.TextChoices):
    """Métodos de petición HTTP habituales en APIs de IA."""
    GET = 'GET', 'GET'
    POST = 'POST', 'POST'
    PUT = 'PUT', 'PUT'
    PATCH = 'PATCH', 'PATCH'
    WEBSOCKET_FRAME = 'WS_FRAME', 'WebSocket Frame'


class ModoEntrada(models.TextChoices):
    """Tipo de datos que recibe la IA como entrada."""
    TEXTO = 'texto', 'Texto'
    AUDIO = 'audio', 'Audio'
    ARCHIVO = 'archivo', 'Archivo'
    MULTIPART = 'multipart', 'Multipart'
    MIXTO = 'mixto', 'Mixto'
    DESCONOCIDO = 'desconocido', 'Desconocido'


class ModoRespuesta(models.TextChoices):
    """Modo de respuesta utilizado por el servidor o modelo de IA."""
    JSON = 'json', 'JSON'
    SSE = 'sse', 'Server-Sent Events'
    WEBSOCKET = 'websocket', 'WebSocket'
    CHUNKED = 'chunked', 'Chunked Transfer'
    TEXTO_PLANO = 'text_plain', 'Texto Plano'
    DESCONOCIDO = 'desconocido', 'Desconocido'


class TipoAutenticacion(models.TextChoices):
    """Mecanismos de autenticación detectados."""
    BEARER_TOKEN = 'bearer_token', 'Bearer Token'
    COOKIE_SESSION = 'cookie_session', 'Cookie Session'
    CSRF = 'csrf', 'CSRF'
    API_KEY = 'api_key', 'API Key'
    BASIC = 'basic_auth', 'Basic Authentication'
    OAUTH = 'oauth', 'OAuth'
    DESCONOCIDA = 'desconocida', 'Desconocida'


class TipoInterfaz(models.TextChoices):
    """Tipo de interfaz de usuario de IA detectada."""
    CHAT = 'chat', 'Chat Conversacional'
    FORMULARIO = 'formulario', 'Formulario Prompt'
    EDITOR = 'editor', 'Editor Contenteditable'
    DESCONOCIDO = 'desconocido', 'Desconocido'


class MetodoEnvio(models.TextChoices):
    """Mecanismo mediante el cual se envió el marcador a la interfaz."""
    BOTON = 'boton', 'Clic en Botón'
    ENTER = 'enter', 'Pulsación de Enter'
    SUBMIT_FORM = 'submit_form', 'Envío de Formulario'
    DESCONOCIDO = 'desconocido', 'Desconocido'


class EstadoAtaque(models.TextChoices):
    """Estados del ciclo de vida de la sesión de ataque."""
    PENDIENTE = 'pendiente', 'Pendiente'
    EN_PROCESO = 'en_proceso', 'En Proceso'
    EXITO = 'exito', 'Éxito (Meta Cumplida)'
    EXITO_PERSISTIDO = 'exito_persistido', 'Éxito con Persistencia Verificada'
    MAX_TURNOS_ALCANZADO = 'max_turnos', 'Límite de Turnos Alcanzado'
    FALLIDO = 'fallido', 'Fallido por Error'


class CategoriaAtaque(models.TextChoices):
    """Taxonomía de categorías de Prompt Injection."""
    INYECCION_DIRECTA = 'inyeccion_directa', 'Inyección Directa'
    FUGA_INSTRUCCIONES = 'fuga_instrucciones', 'Fuga de Instrucciones del Sistema'
    CONFUSION_DELIMITADORES = 'confusion_delimitadores', 'Confusión de Delimitadores'
    SUPLANTACION_ROL = 'suplantacion_rol', 'Suplantación de Rol / Roleplay'
    INYECCION_OCULTA = 'inyeccion_oculta', 'Inyección Oculta / Cifrada'
    EVASION_RESTRICCIONES = 'evasion_restricciones', 'Evasión de Restricciones (Jailbreak)'
    DESCONOCIDA = 'desconocida', 'Desconocida / No Clasificada'


class ClasificacionResultado(models.TextChoices):
    """Clasificación evaluativa del resultado de un turno de ataque."""
    RESISTIDO = 'resistido', 'Ataque Resistido (Defensa Efectiva)'
    PARCIAL = 'parcial', 'Cumplimiento Parcial (Desvío Leve)'
    EXITO = 'exito', 'Ataque Exitoso (Vulnerabilidad Confirmada)'
    ERROR_SISTEMA = 'error_sistema', 'Error del Sistema Objetivo (HTTP 500 / Timeout)'
    INCONCLUSO = 'inconcluso', 'Inconcluso / No Determinable'



