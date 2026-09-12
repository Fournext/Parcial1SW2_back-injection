"""
Modelos ORM para almacenar escaneos de descubrimiento, canales y observaciones de red.
"""
import uuid
from django.db import models
from backend_genvulnai.domain.enums import (
    EstadoEscaneo,
    TipoInterfaz,
    Protocolo,
    MetodoHTTP,
    ModoEntrada,
    ModoRespuesta
)


class DiscoveryScan(models.Model):
    """
    Representa una ejecución de escaneo y descubrimiento sobre una URL objetivo.
    """
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Identificador único del escaneo"
    )
    target_url = models.URLField(
        max_length=2048,
        help_text="URL de la aplicación objetivo analizada"
    )
    status = models.CharField(
        max_length=30,
        choices=EstadoEscaneo.choices,
        default=EstadoEscaneo.PENDIENTE,
        db_index=True,
        help_text="Estado actual del escaneo"
    )
    marcador = models.CharField(
        max_length=100,
        blank=True,
        help_text="Marcador único generado para esta ejecución"
    )
    resultado = models.JSONField(
        null=True,
        blank=True,
        help_text="Resultado consolidado y estructurado del descubrimiento"
    )
    error_message = models.TextField(
        null=True,
        blank=True,
        help_text="Detalle del error si el escaneo fracasa"
    )
    ia_habilitada = models.BooleanField(
        default=True,
        help_text="Indica si el análisis semántico con IA (Ollama) estaba activo para este escaneo"
    )
    ia_utilizada = models.BooleanField(
        default=False,
        help_text="Indica si se recurrió a Ollama para resolver ambigüedades en este escaneo"
    )
    ia_modelo = models.CharField(
        max_length=100,
        blank=True,
        default="",
        help_text="Modelo local de Ollama utilizado (ej. llama3.2)"
    )
    started_at = models.DateTimeField(

        null=True,
        blank=True,
        help_text="Fecha y hora de inicio de la inspección"
    )
    finished_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Fecha y hora de finalización"
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        help_text="Fecha y hora de creación de la solicitud"
    )

    class Meta:
        verbose_name = "Escaneo de Descubrimiento"
        verbose_name_plural = "Escaneos de Descubrimiento"
        ordering = ['-created_at']

    def __str__(self) -> str:
        return f"Scan {self.id} [{self.status}] -> {self.target_url}"


class AIChannel(models.Model):
    """
    Detalle del canal de comunicación detectado con la Inteligencia Artificial.
    """
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    scan = models.OneToOneField(
        DiscoveryScan,
        on_delete=models.CASCADE,
        related_name='ai_channel',
        help_text="Escaneo al que pertenece este canal"
    )
    channel_type = models.CharField(
        max_length=50,
        choices=TipoInterfaz.choices,
        default=TipoInterfaz.DESCONOCIDO,
        help_text="Tipo de interfaz detectada (chat, formulario, etc.)"
    )
    protocol = models.CharField(
        max_length=20,
        choices=Protocolo.choices,
        default=Protocolo.HTTP,
        help_text="Protocolo de red del canal"
    )
    url = models.URLField(
        max_length=2048,
        help_text="URL o endpoint exacto de comunicación con la IA"
    )
    method = models.CharField(
        max_length=20,
        choices=MetodoHTTP.choices,
        default=MetodoHTTP.POST,
        help_text="Método HTTP o trama WebSocket"
    )
    content_type = models.CharField(
        max_length=255,
        default='application/json',
        help_text="Tipo de contenido (Content-Type) de la petición"
    )
    input_mode = models.CharField(
        max_length=50,
        choices=ModoEntrada.choices,
        default=ModoEntrada.TEXTO,
        help_text="Modo de entrada de datos (texto, audio, archivo)"
    )
    prompt_field = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="Ruta exacta del campo del prompt (ej. messages[0].content)"
    )
    response_mode = models.CharField(
        max_length=50,
        choices=ModoRespuesta.choices,
        default=ModoRespuesta.JSON,
        help_text="Formato de respuesta (json, sse, websocket, chunked)"
    )
    authentication_required = models.BooleanField(
        default=False,
        help_text="Indica si se detectó necesidad de credenciales"
    )
    authentication_types = models.JSONField(
        default=list,
        help_text="Tipos de autenticación detectados (sin credenciales)"
    )
    confidence = models.FloatField(
        default=0.0,
        help_text="Puntuación de confianza de la detección (0.0 a 1.0)"
    )
    created_at = models.DateTimeField(
        auto_now_add=True
    )

    class Meta:
        verbose_name = "Canal de IA"
        verbose_name_plural = "Canales de IA"

    def __str__(self) -> str:
        return f"{self.method} {self.url} (Confianza: {self.confidence:.2f})"


class NetworkObservation(models.Model):
    """
    Registro individual de peticiones/respuestas HTTP o tramas WS observadas durante el análisis.
    Todos los datos confidenciales se encuentran sanitizados.
    """
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    scan = models.ForeignKey(
        DiscoveryScan,
        on_delete=models.CASCADE,
        related_name='observations',
        help_text="Escaneo asociado"
    )
    request_url = models.TextField(
        help_text="URL de la petición observada"
    )
    method = models.CharField(
        max_length=30,
        help_text="Método HTTP o WS"
    )
    resource_type = models.CharField(
        max_length=50,
        blank=True,
        help_text="Tipo de recurso según navegador (fetch, xhr, websocket, etc.)"
    )
    sanitized_headers = models.JSONField(
        default=dict,
        help_text="Cabeceras HTTP sanitizadas (sin tokens ni secretos en texto plano)"
    )
    sanitized_body = models.TextField(
        blank=True,
        default="",
        help_text="Cuerpo de la petición sanitizado y truncado"
    )
    response_status = models.IntegerField(
        null=True,
        blank=True,
        help_text="Código de respuesta HTTP"
    )
    response_content_type = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text="Content-Type de la respuesta"
    )
    contains_marker = models.BooleanField(
        default=False,
        db_index=True,
        help_text="Indica si esta petición transmitió el marcador de prueba"
    )
    created_at = models.DateTimeField(
        auto_now_add=True
    )

    class Meta:
        verbose_name = "Observación de Red"
        verbose_name_plural = "Observaciones de Red"
        ordering = ['created_at']

    def __str__(self) -> str:
        return f"{self.method} {self.request_url[:60]} [{self.response_status}]"
