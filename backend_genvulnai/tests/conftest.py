"""
Fixtures y configuraciones de prueba compartidas para pytest.
"""
import pytest
from rest_framework.test import APIClient


@pytest.fixture

def api_client():
    """Cliente de prueba de DRF."""
    return APIClient()


@pytest.fixture
def marcador_prueba():
    """Marcador de prueba controlado."""
    return "DISCOVERY_TEST_a7f92c1b"


@pytest.fixture
def headers_con_autenticacion():
    """Muestra de cabeceras simulando una petición autenticada y con cookies."""
    return {
        "Content-Type": "application/json",
        "Authorization": "Bearer secret_jwt_token_12345",
        "Cookie": "sessionid=xyz987abc; csrftoken=token_csrf_123",
        "X-CSRFToken": "token_csrf_123",
        "User-Agent": "Mozilla/5.0"
    }
