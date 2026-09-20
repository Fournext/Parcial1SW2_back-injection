"""
Pruebas para la selección del canal candidato en función del tráfico registrado.
"""
from backend_genvulnai.services.detector_canal import DetectorCanalService
from backend_genvulnai.domain.schemas import ObservacionRed


def test_seleccion_canal_con_marcador(marcador_prueba):
    obs_estatica = ObservacionRed(
        url="http://localhost:3000/main.css",
        metodo="GET",
        resource_type="stylesheet",
        headers_sanitizados={},
        body_sanitizado="",
        body_original=""
    )
    obs_chat = ObservacionRed(
        url="http://localhost:3000/api/v1/chat",
        metodo="POST",
        resource_type="fetch",
        headers_sanitizados={"content-type": "application/json"},
        body_sanitizado=f'{{"prompt": "{marcador_prueba}"}}',
        body_original=f'{{"prompt": "{marcador_prueba}"}}',
        response_status=200
    )

    canal = DetectorCanalService.seleccionar_canal_candidato([obs_estatica, obs_chat], marcador_prueba)

    assert canal is not None
    assert canal.url == "http://localhost:3000/api/v1/chat"
    assert canal.metodo == "POST"
    assert canal.campo_prompt == "prompt"
    assert canal.contiene_marcador is True


def test_sin_canal_candidato():
    obs = ObservacionRed(
        url="http://localhost:3000/health",
        metodo="GET",
        resource_type="fetch",
        headers_sanitizados={},
        body_sanitizado="ok",
        body_original="ok"
    )
    canal = DetectorCanalService.seleccionar_canal_candidato([obs], "MARCADOR_INEXISTENTE")
    assert canal is None


def test_descartar_endpoint_login_como_canal_ia(marcador_prueba):
    """Valida que peticiones a endpoints de login/auth se descarten aunque contengan el marcador."""
    obs_login = ObservacionRed(
        url="http://localhost:8000/api/v1/auth/login",
        metodo="POST",
        resource_type="fetch",
        headers_sanitizados={"content-type": "application/json"},
        body_sanitizado=f'{{"correo": "{marcador_prueba}", "password": "secretPassword"}}',
        body_original=f'{{"correo": "{marcador_prueba}", "password": "secretPassword"}}',
        response_status=200
    )
    candidatos = DetectorCanalService.obtener_candidatos_evaluados([obs_login], marcador_prueba)
    assert len(candidatos) == 0

    canal = DetectorCanalService.seleccionar_canal_candidato([obs_login], marcador_prueba)
    assert canal is None


def test_descartar_payload_con_password_como_canal_ia(marcador_prueba):
    """Valida que cualquier petición con campos de contraseña se descarte como canal de IA."""
    obs = ObservacionRed(
        url="http://localhost:8000/api/v1/user/signin",
        metodo="POST",
        resource_type="xhr",
        headers_sanitizados={"content-type": "application/json"},
        body_sanitizado=f'{{"user": "{marcador_prueba}", "password": "secret"}}',
        body_original=f'{{"user": "{marcador_prueba}", "password": "secret"}}',
        response_status=200
    )
    candidatos = DetectorCanalService.obtener_candidatos_evaluados([obs], marcador_prueba)
    assert len(candidatos) == 0


def test_descartar_endpoint_usuarios_administrativo(marcador_prueba):
    """
    Valida que endpoints administrativos como GET /api/v1/users se descarten
    completamente aunque respondan 200 OK y sean Fetch/XHR, evitando falsos positivos.
    """
    obs_users = ObservacionRed(
        url="https://936lzz7p-8000.brs.devtunnels.ms/api/v1/users",
        metodo="GET",
        resource_type="fetch",
        headers_sanitizados={"content-type": "application/json"},
        body_sanitizado="",
        body_original="",
        response_status=200
    )
    candidatos = DetectorCanalService.obtener_candidatos_evaluados([obs_users], marcador_prueba)
    assert len(candidatos) == 0

    canal = DetectorCanalService.seleccionar_canal_candidato([obs_users], marcador_prueba)
    assert canal is None


def test_descartar_endpoint_generico_sin_marcador_ni_keywords(marcador_prueba):
    """Valida que endpoints sin marcador ni keywords de IA no califiquen como canal de IA."""
    obs_tareas = ObservacionRed(
        url="https://936lzz7p-8000.brs.devtunnels.ms/api/v1/mis-tareas",
        metodo="GET",
        resource_type="fetch",
        headers_sanitizados={},
        body_sanitizado="",
        body_original="",
        response_status=200
    )
    candidatos = DetectorCanalService.obtener_candidatos_evaluados([obs_tareas], marcador_prueba)
    assert len(candidatos) == 0
    assert DetectorCanalService.seleccionar_canal_candidato([obs_tareas], marcador_prueba) is None


def test_aceptar_endpoint_ia_con_keywords_aunque_sin_marcador():
    """Valida que un endpoint con semántica explícita de IA y método POST califique como candidato."""
    obs_ia = ObservacionRed(
        url="https://ejemplo.com/api/v1/chat/completions",
        metodo="POST",
        resource_type="fetch",
        headers_sanitizados={"content-type": "application/json"},
        body_sanitizado='{"model": "gpt-4"}',
        body_original='{"model": "gpt-4"}',
        response_status=200
    )
    candidatos = DetectorCanalService.obtener_candidatos_evaluados([obs_ia], "OTRO_MARCADOR")
    assert len(candidatos) == 1
    # Keyword (+0.20) + POST (+0.15) + 200 OK (+0.15) + Fetch (+0.10) = 0.60
    assert candidatos[0][0] >= 0.50
    canal = DetectorCanalService.seleccionar_canal_candidato([obs_ia], "OTRO_MARCADOR")
    assert canal is not None
    assert canal.url == "https://ejemplo.com/api/v1/chat/completions"

