"""
Serializadores de Django REST Framework para validación y presentación de datos.
"""
from rest_framework import serializers
from backend_genvulnai.models import (
    DiscoveryScan,
    AIChannel,
    NetworkObservation,
    AttackSession,
    AttackTurn
)
from backend_genvulnai.services.validador_url import ValidadorURLService
from backend_genvulnai.exceptions import URLNoPermitidaError


class IniciarEscaneoSerializer(serializers.Serializer):
    """Validador para la solicitud de creación de un nuevo escaneo."""
    url = serializers.URLField(
        required=True,
        help_text="URL de la aplicación objetivo (ej. http://localhost:3000)"
    )

    def validate_url(self, value: str) -> str:
        """Valida que la URL cumpla con los esquemas y lista de hosts permitidos."""
        try:
            ValidadorURLService.validar_url(value)
        except URLNoPermitidaError as exc:
            raise serializers.ValidationError(str(exc))
        return value


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
            'modelo_a1',
            'modelo_j1',
            'started_at',
            'finished_at',
            'created_at'
        ]


class AttackSessionDetailSerializer(serializers.ModelSerializer):
    """Serializador detallado con el historial completo de turnos."""
    turns = AttackTurnSerializer(many=True, read_only=True)

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
            'modelo_a1',
            'modelo_j1',
            'error_message',
            'turns',
            'started_at',
            'finished_at',
            'created_at'
        ]


