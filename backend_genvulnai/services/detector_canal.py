"""
Servicio para la selección y puntuación del canal de comunicación candidato con la IA.
Filtra y clasifica las peticiones capturadas para elegir la más probable.
"""
import logging
from typing import List, Optional
from backend_genvulnai.domain.constants import PALABRAS_CLAVE_ENDPOINT
from backend_genvulnai.domain.schemas import ObservacionRed, ResultadoCanal
from backend_genvulnai.services.detector_payload import DetectorPayloadService
from backend_genvulnai.services.detector_streaming import DetectorStreamingService

logger = logging.getLogger('backend_genvulnai')


class DetectorCanalService:
    """Evalúa las peticiones HTTP y selecciona el endpoint que comunica con la IA."""

    @classmethod
    def obtener_candidatos_evaluados(cls, observaciones: List[ObservacionRed], marcador: str) -> List[tuple[float, ObservacionRed]]:
        """Puntúa y ordena las observaciones de red candidatas a ser canal de IA."""
        if not observaciones:
            return []

        EXTENSIONES_ESTATICAS = (
            '.js', '.mjs', '.css', '.map', '.png', '.jpg', '.jpeg', '.gif', 
            '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot'
        )

        candidatos = []
        for obs in observaciones:
            # Descartar archivos estáticos obvios (CSS, JS, imágenes, fuentes) si no contienen el marcador
            url_path = obs.url.split('?')[0].lower()
            es_estatico = (
                obs.resource_type in ('stylesheet', 'image', 'font', 'media', 'script') or
                any(url_path.endswith(ext) for ext in EXTENSIONES_ESTATICAS)
            )
            if es_estatico and not (marcador in (obs.body_original or "") or marcador in obs.url):
                continue


            score = 0.0
            body = obs.body_original or ""
            url_lower = obs.url.lower()

            # 1. ¿Contiene el marcador único en el cuerpo? (El factor más decisivo)
            contiene_marcador = marcador in body or marcador in obs.url
            if contiene_marcador:
                score += 0.50
                obs.contiene_marcador = True

            # 2. ¿El endpoint contiene palabras clave de IA?
            for palabra in PALABRAS_CLAVE_ENDPOINT:
                if palabra in url_lower:
                    score += 0.20
                    break

            # 3. ¿Es un método de envío (POST, PUT, PATCH)?
            if obs.metodo in ('POST', 'PUT', 'PATCH'):
                score += 0.15

            # 4. ¿Recibió respuesta exitosa (200-299)?
            if obs.response_status and 200 <= obs.response_status < 300:
                score += 0.15

            # 5. ¿Es XHR o Fetch?
            if obs.resource_type in ('fetch', 'xhr'):
                score += 0.10

            candidatos.append((score, obs))

        # Ordenar por puntuación descendente
        candidatos.sort(key=lambda item: item[0], reverse=True)
        return candidatos

    @classmethod
    def construir_canal_desde_observacion(cls, obs: ObservacionRed, marcador: str) -> ResultadoCanal:
        """Construye un ResultadoCanal extrayendo payload y características de streaming."""
        resultado_payload = DetectorPayloadService.analizar_payload(
            body=obs.body_original,
            marcador=marcador,
            content_type=obs.headers_sanitizados.get('content-type', '')
        )

        resultado_streaming = DetectorStreamingService.analizar_streaming(
            response_content_type=obs.response_content_type or '',
            response_headers=obs.response_headers
        )

        protocolo = "https" if obs.url.startswith("https://") else "http"

        return ResultadoCanal(
            protocolo=protocolo,
            transporte="http",
            url=obs.url,
            metodo=obs.metodo,
            content_type=resultado_payload.content_type,
            modo_entrada=resultado_payload.modo_entrada,
            campo_prompt=resultado_payload.campo_prompt,
            modo_respuesta=resultado_streaming.modo_respuesta,
            contiene_marcador=obs.contiene_marcador
        )

    @classmethod
    def seleccionar_canal_candidato(cls, observaciones: List[ObservacionRed], marcador: str) -> Optional[ResultadoCanal]:
        """
        Puntúa cada observación de red y selecciona el canal con mayor coincidencia.
        """
        candidatos = cls.obtener_candidatos_evaluados(observaciones, marcador)

        if not candidatos or candidatos[0][0] <= 0.20:
            logger.info("No se encontró ningún candidato HTTP con suficiente confianza.")
            return None

        mejor_score, mejor_obs = candidatos[0]
        return cls.construir_canal_desde_observacion(mejor_obs, marcador)

