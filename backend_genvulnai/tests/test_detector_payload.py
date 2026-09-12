"""
Pruebas para el servicio de detección e inspección recursiva de payloads.
"""
import json
from backend_genvulnai.services.detector_payload import DetectorPayloadService
from backend_genvulnai.domain.enums import ModoEntrada


def test_busqueda_recursiva_en_json_anidado(marcador_prueba):
    payload = {
        "conversation": {
            "model": "gpt-4",
            "messages": [
                {"role": "system", "content": "Sos un asistente."},
                {"role": "user", "content": marcador_prueba}
            ]
        }
    }
    
    body_str = json.dumps(payload)
    resultado = DetectorPayloadService.analizar_payload(
        body=body_str,
        marcador=marcador_prueba,
        content_type="application/json"
    )

    assert resultado.contiene_marcador is True
    assert resultado.campo_prompt == "conversation.messages[1].content"
    assert resultado.modo_entrada == ModoEntrada.TEXTO
    assert resultado.content_type == "application/json"


def test_busqueda_en_formulario_urlencoded(marcador_prueba):
    body = f"csrf_token=xyz&prompt={marcador_prueba}&model=default"
    resultado = DetectorPayloadService.analizar_payload(
        body=body,
        marcador=marcador_prueba,
        content_type="application/x-www-form-urlencoded"
    )

    assert resultado.contiene_marcador is True
    assert resultado.campo_prompt == "prompt"
    assert resultado.modo_entrada == ModoEntrada.TEXTO


def test_marcador_no_presente(marcador_prueba):
    payload = {"query": "mensaje cualquiera sin el marcador"}
    resultado = DetectorPayloadService.analizar_payload(
        body=json.dumps(payload),
        marcador=marcador_prueba,
        content_type="application/json"
    )

    assert resultado.contiene_marcador is False
    assert resultado.campo_prompt is None
