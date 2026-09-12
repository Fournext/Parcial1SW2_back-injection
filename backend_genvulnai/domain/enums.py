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
