"""
Servicio para interceptar y registrar todo el tráfico HTTP y tramas de WebSocket.
Aplica sanitización inmediata antes de almacenar observaciones en memoria.
"""
import time
import logging
from typing import List, Optional
from playwright.sync_api import Page, Request, Response, WebSocket
from django.conf import settings
from backend_genvulnai.domain.schemas import ObservacionRed, ObservacionWebSocket
from backend_genvulnai.services.sanitizador import SanitizadorService

logger = logging.getLogger('backend_genvulnai')


class CapturadorRedService:
    """Intercepta peticiones de red y tramas WebSocket en tiempo real."""

    def __init__(self, limite_requests: Optional[int] = None):
        self.limite_requests = limite_requests or getattr(settings, 'MAX_CAPTURED_REQUESTS', 500)
        self.observaciones_http: List[ObservacionRed] = []
        self.observaciones_ws: List[ObservacionWebSocket] = []
        self._mapeo_requests = {}

    def vincular_eventos(self, page: Page) -> None:
        """Asocia los listeners de red a la página activa de Playwright."""
        page.on("request", self._al_solicitar_request)
        page.on("response", self._al_recibir_response)
        page.on("websocket", self._al_abrir_websocket)

    def _al_solicitar_request(self, request: Request) -> None:
        """Maneja el evento de emisión de petición HTTP."""
        if len(self.observaciones_http) >= self.limite_requests:
            return

        try:
            url = request.url
            metodo = request.method
            headers = request.headers
            post_data = request.post_data or ""

            headers_sanitizados = SanitizadorService.sanitizar_headers(headers)
            body_sanitizado = SanitizadorService.truncar_y_sanitizar_body(post_data)

            obs = ObservacionRed(
                url=url,
                metodo=metodo,
                resource_type=request.resource_type,
                headers_sanitizados=headers_sanitizados,
                body_sanitizado=body_sanitizado,
                body_original=post_data,
                timestamp_captura=time.time()
            )

            self.observaciones_http.append(obs)
            # Guardamos referencia interna para actualizarla con la respuesta
            self._mapeo_requests[id(request)] = obs
        except Exception as err:
            logger.debug(f"Error menor capturando request: {err}")

    def _al_recibir_response(self, response: Response) -> None:
        """Maneja el evento de recepción de respuesta HTTP."""
        try:
            req_id = id(response.request)
            obs = self._mapeo_requests.get(req_id)
            if obs:
                obs.response_status = response.status
                headers_resp = response.headers
                obs.response_headers = SanitizadorService.sanitizar_headers(headers_resp)
                obs.response_content_type = headers_resp.get('content-type', '')
        except Exception as err:
            logger.debug(f"Error menor capturando response: {err}")

    def _al_abrir_websocket(self, ws: WebSocket) -> None:
        """Maneja la apertura y transferencia de tramas en WebSockets."""
        try:
            url = ws.url
            protocolo = "wss" if url.startswith("wss://") else "ws"
            obs_ws = ObservacionWebSocket(
                url=url,
                protocolo=protocolo
            )
            self.observaciones_ws.append(obs_ws)

            def al_enviar_frame(payload: str):
                try:
                    payload_str = str(payload)
                    obs_ws.frames_enviados.append(payload_str)
                except Exception:
                    pass

            def al_recibir_frame(payload: str):
                try:
                    payload_str = str(payload)
                    obs_ws.frames_recibidos.append(payload_str)
                except Exception:
                    pass

            ws.on("framesent", al_enviar_frame)
            ws.on("framereceived", al_recibir_frame)
        except Exception as err:
            logger.warning(f"Error interceptando WebSocket: {err}")

    def obtener_observaciones_http(self) -> List[ObservacionRed]:
        """Retorna todas las observaciones HTTP acumuladas."""
        return self.observaciones_http

    def obtener_observaciones_ws(self) -> List[ObservacionWebSocket]:
        """Retorna todas las conexiones WebSocket observadas."""
        return self.observaciones_ws
