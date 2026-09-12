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
