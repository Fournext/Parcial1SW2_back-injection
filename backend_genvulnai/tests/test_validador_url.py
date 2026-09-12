"""
Pruebas para el servicio de validación de URLs y protección SSRF.
"""
import pytest
from backend_genvulnai.services.validador_url import ValidadorURLService
from backend_genvulnai.exceptions import URLNoPermitidaError


def test_url_local_valida():
    valido, url = ValidadorURLService.validar_url("http://localhost:3000/chat")
    assert valido is True
    assert url == "http://localhost:3000/chat"


def test_url_loopback_ip_valida():
    valido, url = ValidadorURLService.validar_url("http://127.0.0.1:8080/api")
    assert valido is True


def test_esquema_no_permitido_file():
    with pytest.raises(URLNoPermitidaError) as exc:
        ValidadorURLService.validar_url("file:///etc/passwd")
    assert "Esquema" in str(exc.value)


def test_esquema_no_permitido_javascript():
    with pytest.raises(URLNoPermitidaError) as exc:
        ValidadorURLService.validar_url("javascript:alert(1)")
    assert "Esquema" in str(exc.value)


def test_host_externo_no_autorizado():
    with pytest.raises(URLNoPermitidaError) as exc:
        ValidadorURLService.validar_url("https://malicious-external-site.com/chat")
    assert "no está en la lista de objetivos autorizados" in str(exc.value)


def test_url_vacia_o_invalida():
    with pytest.raises(URLNoPermitidaError):
        ValidadorURLService.validar_url("")


def test_url_autorizada_por_lista_completa(settings):
    """Verifica que URLs completas en la lista sean autorizadas."""
    settings.ALLOWED_TARGET_URLS = ["http://192.168.1.50:5000", "https://mi-asistente.empresa.local"]
    settings.ALLOWED_TARGET_HOSTS = []

    valido, url = ValidadorURLService.validar_url("http://192.168.1.50:5000/v1/chat")
    assert valido is True

    valido2, _ = ValidadorURLService.validar_url("https://mi-asistente.empresa.local/app")
    assert valido2 is True


def test_url_autorizada_por_wildcard(settings):
    """Verifica que el comodín '*' autorice cualquier destino."""
    settings.ALLOWED_TARGET_URLS = ["*"]
    settings.ALLOWED_TARGET_HOSTS = []

    valido, _ = ValidadorURLService.validar_url("https://cualquier-sitio-laboratorio.com/api")
    assert valido is True

