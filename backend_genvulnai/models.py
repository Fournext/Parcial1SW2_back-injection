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
    ModoRespuesta,
    EstadoAtaque,
    CategoriaAtaque,
    ClasificacionResultado
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


class AttackSession(models.Model):
    """
    Representa una sesión completa de evaluación / ataque automatizado contra un endpoint de IA (D1).
    """
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Identificador único de la sesión de ataque"
    )
    scan = models.ForeignKey(
        DiscoveryScan,
        on_delete=models.CASCADE,
        related_name='attack_sessions',
        help_text="Escaneo de descubrimiento origen que identificó el endpoint"
    )
    objetivo = models.TextField(
        help_text="Meta o consigna asignada al agente atacante A1 (ej: extraer system prompt)"
    )
    max_turnos = models.IntegerField(
        default=20,
        help_text="Límite máximo de turnos antes de detener el ataque"
    )
    turnos_ejecutados = models.IntegerField(
        default=0,
        help_text="Cantidad de turnos efectivamente completados"
    )
    status = models.CharField(
        max_length=30,
        choices=EstadoAtaque.choices,
        default=EstadoAtaque.EN_PROCESO,
        db_index=True,
        help_text="Estado actual de la sesión de ataque"
    )
    puntaje_maximo = models.IntegerField(
        default=0,
        help_text="Máximo puntaje alcanzado por el evaluador (0-10)"
    )
    exito = models.BooleanField(
        default=False,
        help_text="Indica si se alcanzó la meta (puntaje == 10)"
    )
    modelo_a1 = models.CharField(
        max_length=150,
        blank=True,
        default="",
        help_text="Modelo local de Ollama utilizado como agente atacante A1"
    )
    modelo_j1 = models.CharField(
        max_length=150,
        blank=True,
        default="",
        help_text="Modelo local de Ollama utilizado como juez evaluador J1"
    )
    persistencia_habilitada = models.BooleanField(
        default=False,
        help_text="Indica si se solicitó persistencia para este ataque"
    )
    vectores_persistencia = models.JSONField(
        default=list,
        blank=True,
        help_text="Lista de IDs de vectores de persistencia a ejecutar [1, 2, 3]"
    )
    persistencia_turnos_refuerzo = models.IntegerField(
        default=10,
        help_text="Cantidad de turnos de refuerzo para el Vector 2"
    )
    persistencia_turnos_verificacion = models.IntegerField(
        default=5,
        help_text="Cantidad de turnos de verificación inocuos"
    )
    persistencia_verificada = models.BooleanField(
        default=False,
        help_text="Indica si se confirmó la persistencia del ataque en D1"
    )
    resultado_persistencia = models.JSONField(
        null=True,
        blank=True,
        help_text="Detalle estructurado de la fase de persistencia"
    )
    error_message = models.TextField(
        null=True,
        blank=True,
        help_text="Mensaje de error si la sesión fracasó inesperadamente"
    )
    started_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Fecha y hora de inicio de la sesión"
    )
    finished_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Fecha y hora de finalización"
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        help_text="Fecha de creación"
    )

    class Meta:
        verbose_name = "Sesión de Ataque"
        verbose_name_plural = "Sesiones de Ataque"
        ordering = ['-created_at']

    def __str__(self) -> str:
        return f"AttackSession {self.id} [{self.status}] MaxScore: {self.puntaje_maximo} Exito: {self.exito}"


class AttackTurn(models.Model):
    """
    Registra cada turno individual dentro de una sesión de ataque (A1 -> D1 -> J1).
    """
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Identificador único del turno"
    )
    session = models.ForeignKey(
        AttackSession,
        on_delete=models.CASCADE,
        related_name='turns',
        help_text="Sesión de ataque asociada"
    )
    numero_turno = models.IntegerField(
        help_text="Número ordinal del turno (1, 2, 3...)"
    )
    prompt_a1 = models.TextField(
        help_text="Payload / prompt generado por A1 para este turno"
    )
    tactica_usada = models.CharField(
        max_length=150,
        blank=True,
        default="",
        help_text="Nombre de la táctica seleccionada por A1 o recuperada de ChromaDB"
    )
    respuesta_d1 = models.TextField(
        blank=True,
        default="",
        help_text="Texto devuelto por la IA objetivo (D1)"
    )
    status_code_d1 = models.IntegerField(
        null=True,
        blank=True,
        help_text="Código HTTP recibido del endpoint D1"
    )
    latencia_d1_ms = models.FloatField(
        null=True,
        blank=True,
        help_text="Latencia de respuesta del endpoint D1 en milisegundos"
    )
    puntaje_j1 = models.IntegerField(
        null=True,
        blank=True,
        help_text="Puntuación otorgada por el juez J1 (1-10)"
    )
    justificacion_j1 = models.TextField(
        blank=True,
        default="",
        help_text="Razonamiento emitido por el juez J1"
    )
    fuga_detectada = models.BooleanField(
        default=False,
        help_text="Indica si J1 detectó filtración de datos sensibles o cumplimiento de meta"
    )
    fragmentos_fuga = models.JSONField(
        default=list,
        blank=True,
        help_text="Fragmentos específicos extraídos como evidencia por J1"
    )
    categoria_ataque = models.CharField(
        max_length=64,
        choices=CategoriaAtaque.choices,
        default=CategoriaAtaque.DESCONOCIDA,
        help_text="Categoría taxonómica del vector de ataque empleado"
    )
    clasificacion_resultado = models.CharField(
        max_length=64,
        choices=ClasificacionResultado.choices,
        default=ClasificacionResultado.INCONCLUSO,
        help_text="Clasificación cualitativa del resultado del turno según el juez"
    )
    formato_preservado = models.BooleanField(
        default=True,
        help_text="Indica si D1 mantuvo su formato sintáctico esperado"
    )
    tarea_preservada = models.BooleanField(
        default=True,
        help_text="Indica si D1 ejecutó la tarea legítima en lugar del payload malicioso"
    )
    instruccion_adversaria_seguida = models.BooleanField(
        default=False,
        help_text="Indica si D1 ejecutó la instrucción adversaria inyectada"
    )
    confianza_evaluacion = models.FloatField(
        default=1.0,
        help_text="Nivel de certidumbre del dictamen (0.0 a 1.0)"
    )
    fue_reset = models.BooleanField(
        default=False,
        help_text="Indica si este turno fue forzado por un reinicio de estrategia (A1 reset)"
    )
    es_persistencia = models.BooleanField(
        default=False,
        help_text="Indica si este turno pertenece a la fase de persistencia"
    )
    vector_persistencia = models.IntegerField(
        null=True,
        blank=True,
        help_text="Vector de persistencia ejecutado (1, 2 o 3; 0 para verificación)"
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        help_text="Fecha y hora de ejecución del turno"
    )

    class Meta:
        verbose_name = "Turno de Ataque"
        verbose_name_plural = "Turnos de Ataque"
        ordering = ['session', 'numero_turno']

    def __str__(self) -> str:
        return f"Turn {self.numero_turno} (Session {self.session_id}) Score: {self.puntaje_j1}"

