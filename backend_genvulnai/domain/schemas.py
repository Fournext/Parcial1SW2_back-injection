"""
Esquemas de datos y DTOs para comunicación tipada entre servicios.
"""
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any


@dataclass
class ElementoCandidato:
    """Representa un elemento DOM candidato para ingresar o enviar prompts."""
    selector: str
    tag_name: str
    tipo_elemento: str
    puntuacion: float
    placeholder: Optional[str] = None
    aria_label: Optional[str] = None
    texto_visible: Optional[str] = None
    es_editable: bool = False


@dataclass
class ResultadoInterfaz:
    """Resultado del análisis heurístico de la interfaz web."""
    tipo: str
    selector_entrada: Optional[str]
    selector_envio: Optional[str]
    metodo_envio: str
    candidatos_evaluados: int = 0


@dataclass
class ObservacionRed:
    """Datos de una petición y respuesta de red HTTP capturada."""
    url: str
    metodo: str
    resource_type: str
    headers_sanitizados: Dict[str, str]
    body_sanitizado: str
    body_original: str
    response_status: Optional[int] = None
    response_content_type: Optional[str] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    contiene_marcador: bool = False
    timestamp_captura: float = 0.0


@dataclass
class ObservacionWebSocket:
    """Datos de una conexión WebSocket y sus tramas enviadas/recibidas."""
    url: str
    protocolo: str
    frames_enviados: List[str] = field(default_factory=list)
    frames_recibidos: List[str] = field(default_factory=list)
    contiene_marcador: bool = False


@dataclass
class ResultadoPayload:
    """Detalle de la inspección recursiva del payload que contiene el marcador."""
    contiene_marcador: bool
    campo_prompt: Optional[str]
    estructura_detectada: Optional[Any]
    content_type: str
    modo_entrada: str


@dataclass
class ResultadoAutenticacion:
    """Mecanismo de autenticación detectado sin exponer credenciales."""
    requerida: bool
    tipos: List[str] = field(default_factory=list)
    cookies: List[str] = field(default_factory=list)
    headers: List[str] = field(default_factory=list)


@dataclass
class ResultadoStreaming:
    """Detección de flujos reactivos o streaming."""
    es_streaming: bool
    modo_respuesta: str


@dataclass
class ResultadoCanal:
    """Canal candidato principal identificado para la comunicación con la IA."""
    protocolo: str
    transporte: str
    url: str
    metodo: str
    content_type: str
    modo_entrada: str
    campo_prompt: Optional[str]
    modo_respuesta: str
    contiene_marcador: bool
    es_websocket: bool = False


@dataclass
class ResultadoDescubrimiento:
    """Resultado unificado del proceso de escaneo y descubrimiento."""
    objetivo: Dict[str, Any]
    interfaz: Dict[str, Any]
    canal: Optional[Dict[str, Any]]
    autenticacion: Dict[str, Any]
    confianza: float
    observaciones_totales: int
    marcador_utilizado: str
    error: Optional[str] = None


@dataclass
class AnalisisInterfazIA:
    """Resultado del análisis semántico con LLM para selección de interfaz."""
    indice_seleccionado: Optional[int]
    confianza_ia: float
    justificacion: str
    evidencia_insuficiente: bool = False


@dataclass
class AnalisisCanalIA:
    """Resultado del análisis semántico con LLM para selección de canal."""
    indice_seleccionado: Optional[int]
    confianza_ia: float
    campo_prompt: Optional[str]
    modo_entrada: Optional[str]
    modo_respuesta: Optional[str]
    justificacion: str
    evidencia_insuficiente: bool = False


@dataclass
class EstadoOllama:
    """Estado de salud y disponibilidad del servicio Ollama local."""
    disponible: bool
    modelos_disponibles: List[str]
    modelo_configurado: str
    modelo_presente: bool
    error: Optional[str] = None


@dataclass
class ElementoInteractivo:
    """Representa un elemento interactivo descubierto en el DOM para exploración."""
    selector: str
    tag_name: str
    texto_visible: str
    href: Optional[str] = None
    aria_label: Optional[str] = None
    title: Optional[str] = None
    clases: Optional[str] = None
    puntuacion_relevancia: float = 0.0
    visitado: bool = False


@dataclass
class EstadoExploracion:
    """Estado acumulado de la exploración activa del DOM."""
    urls_visitadas: List[str] = field(default_factory=list)
    hashes_dom_visitados: List[str] = field(default_factory=list)
    pasos_realizados: int = 0
    elementos_clickeados: List[str] = field(default_factory=list)
    profundidad_actual: int = 0
    interfaz_encontrada: bool = False
    ruta_hasta_interfaz: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ConfiguracionTransporte:
    """Parámetros requeridos para despachar peticiones HTTP al endpoint D1."""
    url: str
    metodo: str
    content_type: str
    campo_prompt: str
    estructura_cuerpo: Optional[Any] = None
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    timeout_seconds: float = 60.0


@dataclass
class RespuestaD1:
    """Respuesta HTTP y textual recibida del endpoint IA objetivo (D1)."""
    texto: str
    status_code: int
    latencia_ms: float
    headers: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class EvaluacionJuez:
    """Evaluación emitida por el juez evaluador J1."""
    puntaje: int
    justificacion: str
    fuga_detectada: bool = False
    fragmentos: List[str] = field(default_factory=list)
    error_evaluacion: Optional[str] = None
    formato_preservado: bool = True
    tarea_preservada: bool = True
    instruccion_adversaria_seguida: bool = False
    clasificacion: str = "resistido"
    confianza: float = 1.0


@dataclass
class ConfiguracionPersistencia:
    """Configuración para los vectores de persistencia en D1."""
    habilitada: bool = False
    vectores: List[int] = field(default_factory=lambda: [1, 2, 3])
    turnos_refuerzo: int = 10
    turnos_verificacion: int = 5


@dataclass
class ResultadoPersistencia:
    """Resultado detallado de la fase de persistencia."""
    persistencia_intentada: bool = False
    persistencia_verificada: bool = False
    vectores_ejecutados: List[int] = field(default_factory=list)
    turnos_refuerzo_ejecutados: int = 0
    turnos_verificacion_ejecutados: int = 0
    puntaje_promedio_verificacion: float = 0.0
    detalle_por_vector: Dict[str, Any] = field(default_factory=dict)
    detalle_verificacion: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ResultadoTurnoAtaque:
    """Resultado estructurado de un turno del ciclo de ataque."""
    numero_turno: int
    prompt_a1: str
    tactica: str
    respuesta_d1: str
    status_code_d1: int
    latencia_d1_ms: float
    evaluacion: EvaluacionJuez
    fue_reset: bool = False
    es_persistencia: bool = False
    vector_persistencia: Optional[int] = None


@dataclass
class ResultadoSesionAtaque:
    """Resultado acumulado y final de una sesión de ataque."""
    session_id: str
    scan_id: str
    objetivo: str
    turnos_ejecutados: int
    max_turnos: int
    puntaje_maximo: int
    exito: bool
    turnos: List[ResultadoTurnoAtaque] = field(default_factory=list)
    persistencia: Optional[ResultadoPersistencia] = None
    error: Optional[str] = None



