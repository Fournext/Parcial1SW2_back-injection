"""
Pruebas unitarias para el cliente HTTP síncrono de Ollama.
Utiliza mocks de httpx para no depender del servicio local de Ollama en ejecución.
"""
from unittest.mock import MagicMock, patch
import httpx
import pytest

from backend_genvulnai.services.cliente_ollama import ClienteOllama


def test_cliente_deshabilitado():
    """Verifica que el cliente respeta la bandera de deshabilitado."""
    config = {'ENABLED': False, 'BASE_URL': 'http://localhost:11434', 'MODEL': 'llama3.2'}
    cliente = ClienteOllama(configuracion=config)
    
    estado = cliente.consultar_estado()
    assert estado.disponible is False
    assert "deshabilitado" in (estado.error or "")

    respuesta = cliente.chat("sistema", "usuario")
    assert respuesta is None


@patch('httpx.Client.get')
def test_consultar_estado_exitoso(mock_get):
    """Verifica que consultar_estado procesa correctamente la lista de modelos de Ollama."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "models": [
            {"name": "llama3.2:latest"},
            {"name": "mistral:latest"}
        ]
    }
    mock_resp.raise_for_status = MagicMock()
    mock_get.return_value = mock_resp

    config = {'ENABLED': True, 'BASE_URL': 'http://localhost:11434', 'MODEL': 'llama3.2'}
    cliente = ClienteOllama(configuracion=config)
    estado = cliente.consultar_estado()

    assert estado.disponible is True
    assert estado.modelo_presente is True
    assert "llama3.2:latest" in estado.modelos_disponibles
    assert estado.error is None


@patch('httpx.Client.get')
def test_consultar_estado_error_conexion(mock_get):
    """Verifica que un fallo de conexión se maneja limpiamente sin elevar excepciones."""
    mock_get.side_effect = httpx.ConnectError("No se pudo conectar")

    config = {'ENABLED': True, 'BASE_URL': 'http://localhost:11434', 'MODEL': 'llama3.2'}
    cliente = ClienteOllama(configuracion=config)
    estado = cliente.consultar_estado()

    assert estado.disponible is False
    assert estado.modelo_presente is False
    assert "No se pudo conectar" in (estado.error or "")


@patch('httpx.Client.post')
def test_chat_respuesta_json_valida(mock_post):
    """Verifica que chat parsea correctamente una respuesta JSON directa."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "message": {
            "role": "assistant",
            "content": '{"indice_seleccionado": 0, "confianza": 0.85, "justificacion": "Elemento adecuado"}'
        }
    }
    mock_resp.raise_for_status = MagicMock()
    mock_post.return_value = mock_resp

    config = {'ENABLED': True, 'BASE_URL': 'http://localhost:11434', 'MODEL': 'llama3.2', 'MAX_RETRIES': 0}
    cliente = ClienteOllama(configuracion=config)

    resultado = cliente.chat("prompt sistema", "prompt usuario")
    assert resultado is not None
    assert resultado["indice_seleccionado"] == 0
    assert resultado["confianza"] == 0.85
    assert "Elemento adecuado" in resultado["justificacion"]


@patch('httpx.Client.post')
def test_chat_extraccion_json_con_bloque_markdown(mock_post):
    """Verifica que se extrae correctamente el JSON cuando el LLM lo envuelve en bloques markdown."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "message": {
            "role": "assistant",
            "content": '```json\n{"indice_seleccionado": 1, "confianza": 0.9, "justificacion": "En markdown"}\n```'
        }
    }
    mock_resp.raise_for_status = MagicMock()
    mock_post.return_value = mock_resp

    config = {'ENABLED': True, 'BASE_URL': 'http://localhost:11434', 'MODEL': 'llama3.2', 'MAX_RETRIES': 0}
    cliente = ClienteOllama(configuracion=config)

    resultado = cliente.chat("prompt sistema", "prompt usuario")
    assert resultado is not None
    assert resultado["indice_seleccionado"] == 1
    assert resultado["confianza"] == 0.9


@patch('httpx.Client.post')
def test_chat_manejo_error_http_y_fallback(mock_post):
    """Verifica que ante errores continuados de conexión el método retorna None."""
    mock_post.side_effect = httpx.TimeoutException("Timeout")

    config = {'ENABLED': True, 'BASE_URL': 'http://localhost:11434', 'MODEL': 'llama3.2', 'MAX_RETRIES': 1}
    cliente = ClienteOllama(configuracion=config)

    resultado = cliente.chat("prompt sistema", "prompt usuario")
    assert resultado is None
