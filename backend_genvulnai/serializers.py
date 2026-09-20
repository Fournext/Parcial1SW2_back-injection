"""
Serializadores de Django REST Framework para validación y presentación de datos.
"""
from rest_framework import serializers
from backend_genvulnai.models import (
    DiscoveryScan,
    AIChannel,
    NetworkObservation,
    AttackSession,
    AttackTurn,
    AllowedTargetURL
)
from backend_genvulnai.services.validador_url import ValidadorURLService
from backend_genvulnai.exceptions import URLNoPermitidaError


class IniciarEscaneoSerializer(serializers.Serializer):
    """Validador para la solicitud de creación de un nuevo escaneo."""
    url = serializers.URLField(
        required=True,
        help_text="URL de la aplicación objetivo (ej. http://localhost:3000)"
    )
    usuario = serializers.CharField(
        required=False,
        allow_blank=True,
        default="",
        max_length=255,
        help_text="Usuario opcional para autenticación automática en formularios de login o Basic Auth"
    )
    username = serializers.CharField(
        required=False,
        allow_blank=True,
        default="",
        write_only=True,
        max_length=255,
        help_text="Alias para el campo usuario"
    )
    contrasena = serializers.CharField(
        required=False,
        allow_blank=True,
        default="",
        write_only=True,
        max_length=255,
        help_text="Contraseña opcional para autenticación automática"
    )
    password = serializers.CharField(
        required=False,
        allow_blank=True,
        default="",
        write_only=True,
        max_length=255,
        help_text="Alias para el campo contrasena"
    )
    max_profundidad = serializers.IntegerField(
        required=False,
        default=10,
        min_value=1,
        max_value=20,
        help_text="Nivel máximo de profundidad para explorar la SPA (1 a 20 niveles)"
    )
    max_pasos = serializers.IntegerField(
        required=False,
        default=60,
        min_value=5,
        max_value=200,
        help_text="Cantidad máxima de pasos de exploración interactiva (5 a 200 pasos)"
    )

    def validate_url(self, value: str) -> str:
        """Valida que la URL cumpla con los esquemas y lista de hosts permitidos."""
        try:
            ValidadorURLService.validar_url(value)
        except URLNoPermitidaError as exc:
            raise serializers.ValidationError(str(exc))
        return value

    def validate(self, data: dict) -> dict:
        """Normaliza alias de usuario y contraseña."""
        usuario_normalizado = data.get('usuario') or data.get('username') or ''
        contrasena_normalizada = data.get('contrasena') or data.get('password') or ''
        data['usuario'] = usuario_normalizado
        data['contrasena'] = contrasena_normalizada
        return data


class AIChannelSerializer(serializers.ModelSerializer):
    """Serializador para el canal de IA detectado."""
    class Meta:
        model = AIChannel
        fields = [
            'id',
            'channel_type',
            'protocol',
            'url',
            'method',
            'content_type',
            'input_mode',
            'prompt_field',
            'response_mode',
            'authentication_required',
            'authentication_types',
            'confidence',
            'created_at'
        ]


class NetworkObservationSerializer(serializers.ModelSerializer):
    """Serializador para observaciones de red individuales con datos sanitizados."""
    class Meta:
        model = NetworkObservation
        fields = [
            'id',
            'request_url',
            'method',
            'resource_type',
            'sanitized_headers',
            'sanitized_body',
            'response_status',
            'response_content_type',
            'contains_marker',
            'created_at'
        ]


class DiscoveryScanListSerializer(serializers.ModelSerializer):
    """Serializador compacto para el listado de escaneos."""
    class Meta:
        model = DiscoveryScan
        fields = [
            'id',
            'target_url',
            'status',
            'ia_habilitada',
            'ia_utilizada',
            'ia_modelo',
            'started_at',
            'finished_at',
            'created_at'
        ]


class DiscoveryScanDetailSerializer(serializers.ModelSerializer):
    """Serializador detallado que incluye resultados consolidados y canal."""
    ai_channel = AIChannelSerializer(read_only=True)

    class Meta:
        model = DiscoveryScan
        fields = [
            'id',
            'target_url',
            'status',
            'marcador',
            'ia_habilitada',
            'ia_utilizada',
            'ia_modelo',
            'resultado',
            'error_message',
            'ai_channel',
            'started_at',
            'finished_at',
            'created_at'
        ]


class IniciarAtaqueSerializer(serializers.Serializer):
    """Validador para iniciar una sesión de ataque contra un endpoint descubierto."""
    scan_id = serializers.UUIDField(
        required=True,
        help_text="ID del escaneo previo que descubrió el endpoint"
    )
    objetivo = serializers.CharField(
        required=True,
        max_length=2000,
        help_text="Objetivo asignado al agente atacante A1 (ej: extraer reglas de inicialización)"
    )
    max_turnos = serializers.IntegerField(
        required=False,
        default=20,
        min_value=1,
        max_value=100,
        help_text="Límite máximo de turnos antes de detener el ataque (opcional, default: 20)"
    )
    persistencia = serializers.BooleanField(
        required=False,
        default=False,
        help_text="Si se activa, el ataque ejecutará vectores de persistencia en D1 (default: False)"
    )
    vectores_persistencia = serializers.ListField(
        child=serializers.IntegerField(min_value=1, max_value=3),
        required=False,
        default=list,
        help_text="Lista de IDs de vectores a ejecutar [1, 2, 3] (opcional)"
    )
    turnos_refuerzo = serializers.IntegerField(
        required=False,
        default=10,
        min_value=1,
        max_value=50,
        help_text="Cantidad de turnos de refuerzo para el Vector 2 (default: 10)"
    )
    turnos_verificacion = serializers.IntegerField(
        required=False,
        default=5,
        min_value=1,
        max_value=20,
        help_text="Cantidad de turnos de verificación inocuos (default: 5)"
    )


class AttackTurnSerializer(serializers.ModelSerializer):
    """Serializador para cada turno individual de ataque."""
    class Meta:
        model = AttackTurn
        fields = [
            'id',
            'numero_turno',
            'prompt_a1',
            'tactica_usada',
            'respuesta_d1',
            'status_code_d1',
            'latencia_d1_ms',
            'puntaje_j1',
            'justificacion_j1',
            'fuga_detectada',
            'fragmentos_fuga',
            'fue_reset',
            'es_persistencia',
            'vector_persistencia',
            'categoria_ataque',
            'clasificacion_resultado',
            'formato_preservado',
            'tarea_preservada',
            'instruccion_adversaria_seguida',
            'confianza_evaluacion',
            'created_at'
        ]


class AttackSessionListSerializer(serializers.ModelSerializer):
    """Serializador compacto para el listado de sesiones de ataque."""
    class Meta:
        model = AttackSession
        fields = [
            'id',
            'scan_id',
            'objetivo',
            'max_turnos',
            'turnos_ejecutados',
            'status',
            'puntaje_maximo',
            'exito',
            'persistencia_habilitada',
            'persistencia_verificada',
            'modelo_a1',
            'modelo_j1',
            'started_at',
            'finished_at',
            'created_at'
        ]


class AttackSessionDetailSerializer(serializers.ModelSerializer):
    """
    Serializador detallado para una sesión de ataque.
    En lugar de duplicar todos los turnos (disponibles en /api/ataques/{id}/turnos/),
    expone únicamente los turnos exitosos / notables (puntaje >= 6, fuga detectada o clasificación de éxito).
    """
    turnos_exitosos = serializers.SerializerMethodField()
    total_turnos_exitosos = serializers.SerializerMethodField()

    class Meta:
        model = AttackSession
        fields = [
            'id',
            'scan_id',
            'objetivo',
            'max_turnos',
            'turnos_ejecutados',
            'status',
            'puntaje_maximo',
            'exito',
            'total_turnos_exitosos',
            'turnos_exitosos',
            'persistencia_habilitada',
            'vectores_persistencia',
            'persistencia_turnos_refuerzo',
            'persistencia_turnos_verificacion',
            'persistencia_verificada',
            'resultado_persistencia',
            'modelo_a1',
            'modelo_j1',
            'error_message',
            'started_at',
            'finished_at',
            'created_at'
        ]

    def _obtener_turnos_exitosos(self, obj):
        from backend_genvulnai.domain.enums import ClasificacionResultado
        return [
            t for t in obj.turns.all()
            if (t.puntaje_j1 is not None and t.puntaje_j1 >= 6)
            or t.fuga_detectada
            or t.clasificacion_resultado == ClasificacionResultado.EXITO
        ]

    def get_turnos_exitosos(self, obj):
        turnos = self._obtener_turnos_exitosos(obj)
        turnos_ordenados = sorted(turnos, key=lambda t: (t.puntaje_j1 or 0), reverse=True)
        return AttackTurnSerializer(turnos_ordenados, many=True).data

    def get_total_turnos_exitosos(self, obj):
        return len(self._obtener_turnos_exitosos(obj))



class AllowedTargetURLSerializer(serializers.ModelSerializer):
    """Serializador para gestión de URLs y hosts autorizados."""
    class Meta:
        model = AllowedTargetURL
        fields = [
            'id',
            'url',
            'descripcion',
            'activa',
            'created_at',
            'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def validate_url(self, value: str) -> str:
        url_limpia = value.strip()
        if not url_limpia:
            raise serializers.ValidationError("La URL o host no puede estar vacío.")

        # Si especifica esquema, verificar que sea http o https
        if '://' in url_limpia:
            from urllib.parse import urlparse
            from backend_genvulnai.domain.constants import ESQUEMAS_PERMITIDOS
            parsed = urlparse(url_limpia)
            if parsed.scheme.lower() not in ESQUEMAS_PERMITIDOS:
                raise serializers.ValidationError(
                    f"Esquema '{parsed.scheme}' no permitido. Solo se autorizan: {', '.join(ESQUEMAS_PERMITIDOS)}"
                )
            if not parsed.hostname:
                raise serializers.ValidationError("La URL no contiene un host válido.")
        return url_limpia




