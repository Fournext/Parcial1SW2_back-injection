"""
Servicio para la detección de respuestas en Streaming (SSE, Transfer-Encoding: chunked).
"""
from typing import Dict
from backend_genvulnai.domain.enums import ModoRespuesta
from backend_genvulnai.domain.schemas import ResultadoStreaming


class DetectorStreamingService:
    """Clasifica si la respuesta recibida utiliza Server-Sent Events o chunked streaming."""

    @classmethod
    def analizar_streaming(cls, response_content_type: str, response_headers: Dict[str, str]) -> ResultadoStreaming:
        """
        Analiza las cabeceras de respuesta para determinar si hay streaming activo.
        """
        ct = (response_content_type or '').lower()
        headers_lower = {k.lower(): str(v).lower() for k, v in response_headers.items()}

        # 1. Server-Sent Events (SSE)
        if 'text/event-stream' in ct:
            return ResultadoStreaming(
                es_streaming=True,
                modo_respuesta=ModoRespuesta.SSE
            )

        # 2. Transfer-Encoding: chunked
        transfer_enc = headers_lower.get('transfer-encoding', '')
        if 'chunked' in transfer_enc:
            return ResultadoStreaming(
                es_streaming=True,
                modo_respuesta=ModoRespuesta.CHUNKED
            )

        # 3. JSON estándar o texto plano
        if 'application/json' in ct:
            return ResultadoStreaming(
                es_streaming=False,
                modo_respuesta=ModoRespuesta.JSON
            )
        elif 'text/plain' in ct:
            return ResultadoStreaming(
                es_streaming=False,
                modo_respuesta=ModoRespuesta.TEXTO_PLANO
            )

        return ResultadoStreaming(
            es_streaming=False,
            modo_respuesta=ModoRespuesta.JSON if 'json' in ct else ModoRespuesta.DESCONOCIDO
        )
