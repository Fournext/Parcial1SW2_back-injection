"""
Pruebas para el servicio de detección segura de autenticación.
"""
from backend_genvulnai.services.detector_autenticacion import DetectorAutenticacionService
from backend_genvulnai.domain.enums import TipoAutenticacion


def test_deteccion_bearer_token():
    headers = {"Authorization": "Bearer [REDACTADO]", "Content-Type": "application/json"}
    resultado = DetectorAutenticacionService.analizar_autenticacion(headers)

    assert resultado.requerida is True
    assert TipoAutenticacion.BEARER_TOKEN in resultado.tipos
    assert "Authorization" in resultado.headers


def test_deteccion_cookie_session_y_csrf():
    headers = {
        "Cookie": "sessionid=[REDACTADO]; csrftoken=[REDACTADO]",
        "X-CSRFToken": "[REDACTADO]"
    }
    resultado = DetectorAutenticacionService.analizar_autenticacion(headers)

    assert resultado.requerida is True
    assert TipoAutenticacion.COOKIE_SESSION in resultado.tipos
    assert TipoAutenticacion.CSRF in resultado.tipos
    assert "sessionid" in resultado.cookies
    assert "csrftoken" in resultado.cookies
    assert "X-CSRFToken" in resultado.headers


def test_sin_autenticacion():
    headers = {"Content-Type": "application/json", "User-Agent": "Playwright"}
    resultado = DetectorAutenticacionService.analizar_autenticacion(headers)

    assert resultado.requerida is False
    assert len(resultado.tipos) == 0
    assert len(resultado.cookies) == 0
