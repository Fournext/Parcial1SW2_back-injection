"""
Repositorio para la persistencia y consulta desacoplada de escaneos, canales y observaciones.
"""
from typing import Optional, List, Dict, Any
from django.utils import timezone
from django.db import transaction
from backend_genvulnai.domain.enums import EstadoEscaneo
from backend_genvulnai.domain.schemas import ObservacionRed, ResultadoCanal
from backend_genvulnai.models import DiscoveryScan, AIChannel, NetworkObservation


class DescubrimientoRepository:
    """Encapsula las operaciones del ORM para garantizar persistencia limpia y atómica."""

    @classmethod
    def crear_escaneo(cls, url: str) -> DiscoveryScan:
        """Crea un registro de escaneo inicial en estado PENDIENTE."""
        return DiscoveryScan.objects.create(
            target_url=url,
            status=EstadoEscaneo.PENDIENTE
        )

    @classmethod
    def iniciar_escaneo(cls, scan_id: str, marcador: str) -> None:
        """Actualiza el escaneo al estado EN_PROGRESO con su marcador único."""
        DiscoveryScan.objects.filter(id=scan_id).update(
            status=EstadoEscaneo.EN_PROGRESO,
            marcador=marcador,
            started_at=timezone.now()
        )

    @classmethod
    def completar_escaneo(cls, scan_id: str, resultado: Dict[str, Any]) -> None:
        """Marca el escaneo como COMPLETADO y almacena el resultado estructurado."""
        DiscoveryScan.objects.filter(id=scan_id).update(
            status=EstadoEscaneo.COMPLETADO,
            resultado=resultado,
            finished_at=timezone.now()
        )

    @classmethod
    def fallar_escaneo(cls, scan_id: str, error_msg: str) -> None:
        """Marca el escaneo como FALLIDO con el detalle del error."""
        DiscoveryScan.objects.filter(id=scan_id).update(
            status=EstadoEscaneo.FALLIDO,
            error_message=error_msg,
            finished_at=timezone.now()
        )

    @classmethod
    def actualizar_metadatos_ia(
        cls, 
        scan_id: str, 
        ia_habilitada: bool, 
        ia_utilizada: bool, 
        ia_modelo: str
    ) -> None:
        """Actualiza las banderas de uso y auditoría del modelo de IA local."""
        DiscoveryScan.objects.filter(id=scan_id).update(
            ia_habilitada=ia_habilitada,
            ia_utilizada=ia_utilizada,
            ia_modelo=ia_modelo
        )


    @classmethod
    def guardar_canal(
        cls,
        scan: DiscoveryScan,
        canal: ResultadoCanal,
        tipo_interfaz: str,
        autenticacion_requerida: bool,
        tipos_autenticacion: List[str],
        confianza: float
    ) -> AIChannel:
        """Persiste o actualiza el canal de IA detectado."""
        return AIChannel.objects.create(
            scan=scan,
            channel_type=tipo_interfaz,
            protocol=canal.protocolo,
            url=canal.url,
            method=canal.metodo,
            content_type=canal.content_type,
            input_mode=canal.modo_entrada,
            prompt_field=canal.campo_prompt or "",
            response_mode=canal.modo_respuesta,
            authentication_required=autenticacion_requerida,
            authentication_types=tipos_autenticacion,
            confidence=confianza
        )

    @classmethod
    def guardar_observaciones(cls, scan: DiscoveryScan, observaciones: List[ObservacionRed]) -> None:
        """Persiste por lotes las observaciones de red capturadas."""
        if not observaciones:
            return

        modelos = [
            NetworkObservation(
                scan=scan,
                request_url=obs.url,
                method=obs.metodo,
                resource_type=obs.resource_type,
                sanitized_headers=obs.headers_sanitizados,
                sanitized_body=obs.body_sanitizado,
                response_status=obs.response_status,
                response_content_type=obs.response_content_type or "",
                contains_marker=obs.contiene_marcador
            )
            for obs in observaciones
        ]

        with transaction.atomic():
            NetworkObservation.objects.bulk_create(modelos, batch_size=100)

    @classmethod
    def obtener_por_id(cls, scan_id: str) -> Optional[DiscoveryScan]:
        """Recupera un escaneo por su ID con sus relaciones precargadas."""
        try:
            return DiscoveryScan.objects.select_related('ai_channel').prefetch_related('observations').get(id=scan_id)
        except DiscoveryScan.DoesNotExist:
            return None
