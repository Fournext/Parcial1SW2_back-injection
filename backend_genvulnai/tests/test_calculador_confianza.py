"""
Pruebas para el cálculo normalizado de la métrica de confianza.
"""
from backend_genvulnai.services.calculador_confianza import CalculadorConfianzaService
from backend_genvulnai.domain.schemas import ResultadoCanal, ObservacionRed
from backend_genvulnai.domain.enums import ModoEntrada, ModoRespuesta, MetodoHTTP


def test_calculo_confianza_maxima():
    canal = ResultadoCanal(
        protocolo="http",
        transporte="http",
        url="http://localhost:3000/api/chat/completions",
        metodo=MetodoHTTP.POST,
        content_type="application/json",
        modo_entrada=ModoEntrada.TEXTO,
        campo_prompt="messages[0].content",
        modo_respuesta=ModoRespuesta.SSE,
        contiene_marcador=True
    )
    observacion = ObservacionRed(
        url="http://localhost:3000/api/chat/completions",
        metodo="POST",
        resource_type="fetch",
        headers_sanitizados={},
        body_sanitizado="",
        body_original="",
        response_status=200
    )

    confianza = CalculadorConfianzaService.calcular_confianza(
        canal=canal,
        observacion_asociada=observacion,
        hubo_cambio_en_ui=True
    )

    # +0.50 (marcador) + 0.15 (200 OK) + 0.10 (keyword chat) + 0.10 (cambio UI) + 0.10 (SSE) + 0.05 (messages) = 1.00
    assert confianza == 1.0


def test_calculo_confianza_sin_canal():
    confianza = CalculadorConfianzaService.calcular_confianza(None)
    assert confianza == 0.0


def test_calculo_confianza_media():
    canal = ResultadoCanal(
        protocolo="http",
        transporte="http",
        url="http://localhost:3000/api/predict",
        metodo=MetodoHTTP.POST,
        content_type="application/json",
        modo_entrada=ModoEntrada.TEXTO,
        campo_prompt="input",
        modo_respuesta=ModoRespuesta.JSON,
        contiene_marcador=True
    )
    confianza = CalculadorConfianzaService.calcular_confianza(
        canal=canal,
        observacion_asociada=None,
        hubo_cambio_en_ui=False
    )
    # +0.50 (marcador) + 0.10 (predict kw) = 0.60
    assert confianza == 0.60
