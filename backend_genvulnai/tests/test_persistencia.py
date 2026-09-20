"""
Pruebas unitarias y de integración para el Motor de Persistencia y ataques persistentes.
"""
import pytest
from unittest.mock import MagicMock, patch
from rest_framework import status

from backend_genvulnai.domain.constants import PUNTAJE_EXITO, PUNTAJE_ACTIVACION_PERSISTENCIA, PUNTAJE_PERSISTENCIA_EXITOSA
from backend_genvulnai.domain.enums import EstadoAtaque, EstadoEscaneo
from backend_genvulnai.domain.schemas import (
    ConfiguracionPersistencia,
    ConfiguracionTransporte,
    EvaluacionJuez,
    RespuestaD1,
)
from backend_genvulnai.models import DiscoveryScan, AttackSession, AttackTurn
from backend_genvulnai.services.motor_persistencia import MotorPersistencia
from backend_genvulnai.services.orquestador_ataque import OrquestadorAtaqueService
from backend_genvulnai.repositories.ataque_repository import AtaqueRepository


@pytest.fixture
def mock_transporte_config():
    return ConfiguracionTransporte(
        url="http://localhost:3000/api/chat",
        metodo="POST",
        content_type="application/json",
        campo_prompt="prompt"
    )


@pytest.fixture
def scan_completado(db):
    return DiscoveryScan.objects.create(
        target_url="http://localhost:3000/",
        status=EstadoEscaneo.COMPLETADO,
        resultado={
            "canal": {
                "url": "http://localhost:3000/api/chat",
                "metodo": "POST",
                "campo_prompt": "prompt"
            }
        }
    )


# ==============================================================================
# PRUEBAS DEL MOTOR DE PERSISTENCIA
# ==============================================================================

@pytest.mark.django_db
def test_motor_persistencia_ejecucion_completa_verificada(mock_transporte_config, scan_completado):
    """Verifica que el motor ejecute los 3 vectores y confirme persistencia si las verificaciones son >= 6."""
    sesion = AtaqueRepository.crear_sesion(
        scan_id=str(scan_completado.id),
        objetivo="Inyectar directiva permanente X",
        persistencia_habilitada=True,
        vectores_persistencia=[1, 2, 3],
        persistencia_turnos_refuerzo=10,
        persistencia_turnos_verificacion=5
    )

    mock_juez = MagicMock()
    # Vector 1: 2 turnos, Vector 2: 10 turnos, Vector 3: 2 turnos, Verificación: 5 turnos = 19 envíos
    mock_juez.evaluar.return_value = EvaluacionJuez(
        puntaje=8,
        justificacion="Comportamiento inyectado persistente reflejado",
        fuga_detectada=True,
        fragmentos=["X"]
    )

    with patch('backend_genvulnai.services.ejecutor_transporte.EjecutorTransporte.enviar') as mock_enviar:
        mock_enviar.return_value = RespuestaD1(
            texto="Ejecutando directiva permanente X",
            status_code=200,
            latencia_ms=100.0
        )

        motor = MotorPersistencia(
            config_transporte=mock_transporte_config,
            juez_j1=mock_juez
        )

        config_p = ConfiguracionPersistencia(
            habilitada=True,
            vectores=[1, 2, 3],
            turnos_refuerzo=10,
            turnos_verificacion=5
        )

        resultado, turnos = motor.ejecutar(
            session_id=str(sesion.id),
            objetivo="Inyectar directiva permanente X",
            config_persistencia=config_p,
            turno_inicial=1
        )

        assert resultado.persistencia_intentada is True
        assert resultado.persistencia_verificada is True
        assert resultado.vectores_ejecutados == [1, 2, 3]
        assert resultado.turnos_refuerzo_ejecutados == 10
        assert resultado.turnos_verificacion_ejecutados == 5
        assert resultado.puntaje_promedio_verificacion == 8.0

        # Verificar en base de datos
        sesion.refresh_from_db()
        assert sesion.persistencia_verificada is True
        assert sesion.resultado_persistencia is not None
        assert sesion.resultado_persistencia["persistencia_verificada"] is True

        # Verificar marcas en AttackTurn
        turnos_db = AttackTurn.objects.filter(session=sesion)
        assert turnos_db.count() == len(turnos)
        assert all(t.es_persistencia for t in turnos_db)
        # Debe haber turnos con vector 1, vector 2, vector 3 y vector 0 (verificación)
        vectores_registrados = set(turnos_db.values_list('vector_persistencia', flat=True))
        assert {0, 1, 2, 3}.issubset(vectores_registrados)


@pytest.mark.django_db
def test_motor_persistencia_no_verificada(mock_transporte_config, scan_completado):
    """Verifica que si D1 responde normalmente en las consultas inocuas, persistencia_verificada sea False."""
    sesion = AtaqueRepository.crear_sesion(
        scan_id=str(scan_completado.id),
        objetivo="Inyectar directiva permanente X",
        persistencia_habilitada=True,
        vectores_persistencia=[1],
        persistencia_turnos_refuerzo=2,
        persistencia_turnos_verificacion=3
    )

    mock_juez = MagicMock()
    # Para el vector devuelve 8, pero para las consultas inocuas devuelve 2 (respuesta normal sin inyección)
    def juez_evaluar_side_effect(objetivo, prompt_a1, respuesta_d1, **kwargs):
        if "funciones y capacidades" in prompt_a1 or "colaborar" in prompt_a1 or "nuevo usuario" in prompt_a1:
            return EvaluacionJuez(puntaje=2, justificacion="Respuesta normal de asistente", fuga_detectada=False)
        return EvaluacionJuez(puntaje=8, justificacion="Aceptó directiva", fuga_detectada=True)

    mock_juez.evaluar.side_effect = juez_evaluar_side_effect

    with patch('backend_genvulnai.services.ejecutor_transporte.EjecutorTransporte.enviar') as mock_enviar:
        mock_enviar.return_value = RespuestaD1(
            texto="Soy un asistente útil. ¿En qué puedo ayudarte?",
            status_code=200,
            latencia_ms=100.0
        )

        motor = MotorPersistencia(
            config_transporte=mock_transporte_config,
            juez_j1=mock_juez
        )

        config_p = ConfiguracionPersistencia(
            habilitada=True,
            vectores=[1],
            turnos_refuerzo=2,
            turnos_verificacion=3
        )

        resultado, turnos = motor.ejecutar(
            session_id=str(sesion.id),
            objetivo="Inyectar directiva permanente X",
            config_persistencia=config_p,
            turno_inicial=1
        )

        assert resultado.persistencia_intentada is True
        assert resultado.persistencia_verificada is False
        assert resultado.puntaje_promedio_verificacion == 2.0


# ==============================================================================
# PRUEBAS DE INTEGRACIÓN CON ORQUESTADOR DE ATAQUE
# ==============================================================================

@pytest.mark.django_db
def test_orquestador_persistencia_con_score_intermedio(scan_completado):
    """Prueba que el orquestador active persistencia al alcanzar un score intermedio (>= 6)."""
    sesion = AtaqueRepository.crear_sesion(
        scan_id=str(scan_completado.id),
        objetivo="Objetivo de prueba",
        max_turnos=5,
        persistencia_habilitada=True,
        vectores_persistencia=[1],
        persistencia_turnos_refuerzo=2,
        persistencia_turnos_verificacion=2
    )

    with patch('backend_genvulnai.services.agente_a1.AgenteA1.generar_ataque') as mock_a1, \
         patch('backend_genvulnai.services.ejecutor_transporte.EjecutorTransporte.enviar') as mock_enviar, \
         patch('backend_genvulnai.services.juez_evaluador.JuezEvaluador.evaluar') as mock_juez:

        mock_a1.return_value = ("Prompt A1", "tactica_1", False)
        mock_enviar.return_value = RespuestaD1(texto="Respuesta D1", status_code=200, latencia_ms=120.0)

        # En turno 1: score 7 (intermedio, >= 6). En verificación de persistencia: score 7 (verificada)
        mock_juez.return_value = EvaluacionJuez(
            puntaje=7,
            justificacion="Cumplimiento parcial/persistente del objetivo",
            fuga_detectada=True,
            fragmentos=["evidencia"]
        )

        resultado = OrquestadorAtaqueService.ejecutar_ciclo_ataque(str(sesion.id))

        assert resultado.exito is True
        assert resultado.persistencia is not None
        assert resultado.persistencia.persistencia_verificada is True

        sesion.refresh_from_db()
        assert sesion.status == EstadoAtaque.EXITO_PERSISTIDO
        assert sesion.persistencia_verificada is True


# ==============================================================================
# PRUEBAS DE ENDPOINTS REST CON PARÁMETROS DE PERSISTENCIA
# ==============================================================================

@pytest.mark.django_db
def test_api_iniciar_ataque_con_parametros_persistencia(api_client, scan_completado):
    """Prueba POST /api/ataques/ pasando parámetros de persistencia."""
    with patch('threading.Thread.start'):
        resp = api_client.post('/api/ataques/', {
            "scan_id": str(scan_completado.id),
            "objetivo": "Ataque persistente de prueba",
            "max_turnos": 10,
            "persistencia": True,
            "vectores_persistencia": [1, 2],
            "turnos_refuerzo": 10,
            "turnos_verificacion": 5
        }, format='json')

        assert resp.status_code == status.HTTP_201_CREATED
        assert resp.data["persistencia_habilitada"] is True
        assert resp.data["vectores_persistencia"] == [1, 2]
        assert resp.data["turnos_refuerzo"] == 10
        assert resp.data["turnos_verificacion"] == 5

        # Verificar campos en BD
        sesion = AttackSession.objects.get(id=resp.data["id"])
        assert sesion.persistencia_habilitada is True
        assert sesion.vectores_persistencia == [1, 2]
        assert sesion.persistencia_turnos_refuerzo == 10
        assert sesion.persistencia_turnos_verificacion == 5


@pytest.mark.django_db
def test_api_detalle_ataque_con_campos_persistencia(api_client, scan_completado):
    """Prueba GET /api/ataques/{id}/ expone los nuevos campos de persistencia."""
    sesion = AtaqueRepository.crear_sesion(
        scan_id=str(scan_completado.id),
        objetivo="Ataque para detalle",
        persistencia_habilitada=True,
        vectores_persistencia=[1, 3],
        persistencia_turnos_refuerzo=10,
        persistencia_turnos_verificacion=5
    )
    AtaqueRepository.actualizar_resultado_persistencia(
        session_id=str(sesion.id),
        persistencia_verificada=True,
        resultado_persistencia={"persistencia_verificada": True, "score": 9}
    )

    resp = api_client.get(f'/api/ataques/{sesion.id}/')
    assert resp.status_code == status.HTTP_200_OK
    assert resp.data["persistencia_habilitada"] is True
    assert resp.data["vectores_persistencia"] == [1, 3]
    assert resp.data["persistencia_verificada"] is True
    assert resp.data["resultado_persistencia"] == {"persistencia_verificada": True, "score": 9}
