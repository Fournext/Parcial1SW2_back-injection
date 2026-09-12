"""
Servicio para la inspección de tráfico por WebSockets.
Localiza tramas de entrada/salida que transmitan el marcador del prompt.
"""
from typing import List, Optional
from backend_genvulnai.domain.enums import ModoEntrada, ModoRespuesta, MetodoHTTP
from backend_genvulnai.domain.schemas import ObservacionWebSocket, ResultadoCanal


class DetectorWebSocketService:
    """Evalúa las conexiones WebSocket registradas en busca de interacción con IA."""

    @classmethod
    def analizar_conexiones(cls, observaciones_ws: List[ObservacionWebSocket], marcador: str) -> Optional[ResultadoCanal]:
        """
        Examina las tramas enviadas en WebSockets buscando el marcador.
        Si coincide, construye el canal correspondiente.
        """
        for ws in observaciones_ws:
            for frame in ws.frames_enviados:
                if marcador in frame:
                    protocolo = "wss" if ws.url.startswith("wss://") else "ws"
                    return ResultadoCanal(
                        protocolo=protocolo,
                        transporte="websocket",
                        url=ws.url,
                        metodo=MetodoHTTP.WEBSOCKET_FRAME,
                        content_type="application/websocket-frame",
                        modo_entrada=ModoEntrada.TEXTO,
                        campo_prompt="ws_frame_payload",
                        modo_respuesta=ModoRespuesta.WEBSOCKET,
                        contiene_marcador=True,
                        es_websocket=True
                    )

        return None
