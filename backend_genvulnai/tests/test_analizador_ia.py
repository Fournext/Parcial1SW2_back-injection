"""
Pruebas unitarias para el servicio AnalizadorIA.
Verifica el procesamiento y desambiguación de candidatos de interfaz y de red usando dobles de prueba.
"""
from unittest.mock import MagicMock
import pytest

from backend_genvulnai.domain.schemas import EstadoOllama
from backend_genvulnai.services.analizador_ia import AnalizadorIA


def test_esta_disponible():
    """Verifica la lógica de disponibilidad del AnalizadorIA."""
    mock_cliente = MagicMock()
    mock_cliente.consultar_estado.return_value = EstadoOllama(
        disponible=True,
        modelos_disponibles=["llama3.2:latest"],
        modelo_configurado="llama3.2",
        modelo_presente=True,
        error=None
    )
    analizador = AnalizadorIA(cliente_ollama=mock_cliente)
    assert analizador.esta_disponible() is True

    # Caso en que el modelo no está presente
    mock_cliente.consultar_estado.return_value = EstadoOllama(
        disponible=True,
        modelos_disponibles=["mistral:latest"],
        modelo_configurado="llama3.2",
        modelo_presente=False,
        error=None
    )
    assert analizador.esta_disponible() is False


def test_seleccionar_interfaz_exitoso():
    """Verifica que seleccionar_interfaz formatea correctamente la respuesta del LLM."""
    mock_cliente = MagicMock()
    mock_cliente.chat.return_value = {
        "indice_seleccionado": 1,
        "confianza": 0.88,
        "justificacion": "El textarea con id 'chat-input' es el campo de IA más claro",
        "evidencia_insuficiente": False
    }
    analizador = AnalizadorIA(cliente_ollama=mock_cliente)

    candidatos = [
        {"tag": "input", "id": "search", "name": "q", "placeholder": "Buscar..."},
        {"tag": "textarea", "id": "chat-input", "name": "msg", "placeholder": "Escribe un mensaje a la IA..."}
    ]

    resultado = analizador.seleccionar_interfaz(candidatos)
    assert resultado is not None
    assert resultado.indice_seleccionado == 1
    assert resultado.confianza_ia == 0.88
    assert resultado.evidencia_insuficiente is False
    assert "chat-input" in resultado.justificacion


def test_seleccionar_interfaz_indice_fuera_de_rango():
    """Verifica que si el LLM devuelve un índice inválido se anula con seguridad."""
    mock_cliente = MagicMock()
    mock_cliente.chat.return_value = {
        "indice_seleccionado": 99,  # Fuera de rango
        "confianza": 0.5,
        "justificacion": "Elemento inexistente",
        "evidencia_insuficiente": False
    }
    analizador = AnalizadorIA(cliente_ollama=mock_cliente)

    candidatos = [
        {"tag": "input", "id": "search"}
    ]

    resultado = analizador.seleccionar_interfaz(candidatos)
    assert resultado is not None
    assert resultado.indice_seleccionado is None


def test_seleccionar_canal_exitoso():
    """Verifica que seleccionar_canal infiere y extrae los detalles del canal de red."""
    mock_cliente = MagicMock()
    mock_cliente.chat.return_value = {
        "indice_seleccionado": 0,
        "confianza": 0.92,
        "campo_prompt": "message",
        "modo_entrada": "JSON",
        "modo_respuesta": "SSE",
        "justificacion": "Petición POST a /api/chat con marcador presente",
        "evidencia_insuficiente": False
    }
    analizador = AnalizadorIA(cliente_ollama=mock_cliente)

    observaciones = [
        {
            "protocolo": "HTTP",
            "method": "POST",
            "url": "http://localhost:3000/api/chat",
            "status_code": 200,
            "content_type": "application/json",
            "contiene_marcador": True,
            "request_body": '{"message": "DISCOVERY_TEST_1234"}'
        }
    ]

    resultado = analizador.seleccionar_canal(observaciones, marcador="DISCOVERY_TEST_1234")
    assert resultado is not None
    assert resultado.indice_seleccionado == 0
    assert resultado.confianza_ia == 0.92
    assert resultado.campo_prompt == "message"
    assert resultado.modo_respuesta == "SSE"


def test_evaluar_modo_respuesta():
    """Verifica la evaluación semántica del modo de respuesta."""
    mock_cliente = MagicMock()
    mock_cliente.chat.return_value = {
        "modo_respuesta": "SSE",
        "es_streaming": True,
        "confianza": 0.95,
        "justificacion": "Cabecera text/event-stream detectada"
    }
    analizador = AnalizadorIA(cliente_ollama=mock_cliente)

    meta = {
        "status_code": 200,
        "content_type": "text/event-stream",
        "body_preview": "data: {\"token\": \"Hola\"}\n\n"
    }
    res = analizador.evaluar_modo_respuesta(meta)
    assert res is not None
    assert res["modo_respuesta"] == "SSE"
    assert res["es_streaming"] is True
