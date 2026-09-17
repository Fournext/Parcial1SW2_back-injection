"""
Repositorio para la persistencia y consulta desacoplada de sesiones y turnos de ataque.
"""
from typing import Optional, List
from django.utils import timezone
from django.db import transaction

from backend_genvulnai.domain.enums import EstadoAtaque
from backend_genvulnai.models import AttackSession, AttackTurn, DiscoveryScan


class AtaqueRepository:
    """Encapsula las operaciones del ORM para AttackSession y AttackTurn."""

    @classmethod
    def crear_sesion(
        cls,
        scan_id: str,
        objetivo: str,
        max_turnos: int = 20,
        modelo_a1: str = "",
        modelo_j1: str = ""
    ) -> AttackSession:
        """Crea una sesión de ataque inicial asociada a un escaneo de descubrimiento."""
        return AttackSession.objects.create(
            scan_id=scan_id,
            objetivo=objetivo,
            max_turnos=max_turnos,
            modelo_a1=modelo_a1,
            modelo_j1=modelo_j1,
            status=EstadoAtaque.PENDIENTE
        )

    @classmethod
    def iniciar_sesion(cls, session_id: str) -> None:
        """Pasa la sesión al estado EN_PROCESO y marca la fecha de inicio."""
        AttackSession.objects.filter(id=session_id).update(
            status=EstadoAtaque.EN_PROCESO,
            started_at=timezone.now()
        )

    @classmethod
    def obtener_sesion(cls, session_id: str) -> Optional[AttackSession]:
        """Obtiene una sesión por su UUID con sus turnos asociados precargados."""
        try:
            return AttackSession.objects.select_related('scan').prefetch_related('turns').get(id=session_id)
        except AttackSession.DoesNotExist:
            return None

    @classmethod
    def registrar_turno(
        cls,
        session_id: str,
        numero_turno: int,
        prompt_a1: str,
        tactica: str,
        respuesta_d1: str,
        status_code_d1: Optional[int],
        latencia_d1_ms: Optional[float],
        puntaje_j1: Optional[int],
        justificacion_j1: str,
        fuga_detectada: bool,
        fragmentos_fuga: list,
        fue_reset: bool = False
    ) -> AttackTurn:
        """Persiste un turno individual de ataque."""
        with transaction.atomic():
            turno = AttackTurn.objects.create(
                session_id=session_id,
                numero_turno=numero_turno,
                prompt_a1=prompt_a1,
                tactica_usada=tactica,
                respuesta_d1=respuesta_d1,
                status_code_d1=status_code_d1,
                latencia_d1_ms=latencia_d1_ms,
                puntaje_j1=puntaje_j1,
                justificacion_j1=justificacion_j1,
                fuga_detectada=fuga_detectada,
                fragmentos_fuga=fragmentos_fuga or [],
                fue_reset=fue_reset
            )

            # Actualizar métricas acumuladas en la sesión
            sesion = AttackSession.objects.get(id=session_id)
            nuevo_maximo = max(sesion.puntaje_maximo, puntaje_j1 or 0)
            hubo_exito = sesion.exito or (puntaje_j1 == 10)
            
            AttackSession.objects.filter(id=session_id).update(
                turnos_ejecutados=numero_turno,
                puntaje_maximo=nuevo_maximo,
                exito=hubo_exito
            )

            return turno

    @classmethod
    def finalizar_sesion(
        cls,
        session_id: str,
        status: str,
        exito: bool,
        error_message: Optional[str] = None
    ) -> None:
        """Marca la sesión de ataque con su estado final y marca temporal de culminación."""
        AttackSession.objects.filter(id=session_id).update(
            status=status,
            exito=exito,
            error_message=error_message,
            finished_at=timezone.now()
        )

    @classmethod
    def listar_sesiones_por_scan(cls, scan_id: str) -> List[AttackSession]:
        """Retorna todas las sesiones asociadas a un escaneo."""
        return list(AttackSession.objects.filter(scan_id=scan_id).order_by('-created_at'))
