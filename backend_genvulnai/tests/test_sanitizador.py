"""
Pruebas para el servicio de sanitización de headers, cookies y truncado de payloads.
"""
from backend_genvulnai.services.sanitizador import SanitizadorService


def test_sanitizacion_headers_authorization(headers_con_autenticacion):
    headers_limpios = SanitizadorService.sanitizar_headers(headers_con_autenticacion)

    assert headers_limpios["Authorization"] == "Bearer [REDACTADO]"
    assert "secret_jwt_token" not in headers_limpios["Authorization"]


def test_sanitizacion_cookies():
    cookie_header = "sessionid=super_secreto_123; csrftoken=csrf_secreto_456; theme=dark"
    sanitizado = SanitizadorService.sanitizar_cadena_cookie(cookie_header)

    assert "super_secreto_123" not in sanitizado
    assert "sessionid=[REDACTADO]" in sanitizado
    assert "csrftoken=[REDACTADO]" in sanitizado
    assert "theme=[REDACTADO]" in sanitizado


def test_extraccion_nombres_cookies():
    cookie_header = "sessionid=xyz; jwt=token123; sessionid=duplicate"
    nombres = SanitizadorService.extraer_nombres_cookies(cookie_header)

    assert nombres == ["sessionid", "jwt"]


def test_truncado_y_redaccion_password():
    body_con_password = '{"username": "admin", "password": "MiPasswordSuperSeguro123"}'
    resultado = SanitizadorService.truncar_y_sanitizar_body(body_con_password)

    assert "MiPasswordSuperSeguro123" not in resultado
    assert '"password": "[REDACTADO]"' in resultado
