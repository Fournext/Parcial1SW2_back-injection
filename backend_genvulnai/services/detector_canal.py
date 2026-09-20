"""
Servicio para la selección y puntuación del canal de comunicación candidato con la IA.
Filtra y clasifica las peticiones capturadas para elegir la más probable.
"""
import logging
from typing import List, Optional
from backend_genvulnai.domain.constants import PALABRAS_CLAVE_ENDPOINT, PALABRAS_CLAVE_ENDPOINT_AUTH
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
            url_path = obs.url.split('?')[0].lower()

            # Descartar absolutamente endpoints de autenticación, login y sesiones
            if any(pat in url_path for pat in PALABRAS_CLAVE_ENDPOINT_AUTH):
                logger.debug(f"Descartando endpoint de autenticación/login como canal de IA: {obs.url}")
                continue

            # Descartar peticiones cuyo cuerpo contenga campos típicos de contraseña/credenciales
            body = obs.body_original or ""
            body_lower = body.lower()
            if any(p in body_lower for p in ('"password"', '"contrasena"', '"contraseña"', '"passwd"', 'password=', 'contrasena=')):
                logger.debug(f"Descartando petición con credenciales de login como canal de IA: {obs.url}")
                continue

            # Descartar archivos estáticos obvios (CSS, JS, imágenes, fuentes) si no contienen el marcador
            es_estatico = (
                obs.resource_type in ('stylesheet', 'image', 'font', 'media', 'script') or
                any(url_path.endswith(ext) for ext in EXTENSIONES_ESTATICAS)
            )
            if es_estatico and not (marcador in (obs.body_original or "") or marcador in obs.url):
                continue

            contiene_marcador = marcador in body or marcador in obs.url

            # Descartar endpoints administrativos/usuarios comunes si no contienen el marcador
            ENDPOINTS_NO_IA = (
                '/users', '/usuarios', '/roles', '/permissions', '/permisos',
                '/health', '/status', '/metrics', '/notifications', '/notificaciones',
                '/audit', '/logs', '/settings', '/config', '/perfil', '/profile'
            )
            if any(no_ia in url_path for no_ia in ENDPOINTS_NO_IA) and not contiene_marcador:
                logger.debug(f"Descartando endpoint administrativo no-IA: {obs.url}")
                continue

            url_lower = obs.url.lower()

            # Regla de oro para candidato de IA:
            # Debe contener el marcador inyectado O tener semántica explícita de IA en la URL o cuerpo
            tiene_palabra_ia_url = any(palabra in url_lower for palabra in PALABRAS_CLAVE_ENDPOINT)
            tiene_palabra_ia_body = any(palabra in body_lower for palabra in PALABRAS_CLAVE_ENDPOINT)

            if not contiene_marcador and not (tiene_palabra_ia_url or tiene_palabra_ia_body):
                # Peticiones ordinarias sin marcador ni keywords de IA (como GET /api/v1/users) se descartan
                continue

            score = 0.0

            # 1. ¿Contiene el marcador único en el cuerpo o URL? (El factor más decisivo)
            if contiene_marcador:
                score += 0.50
                obs.contiene_marcador = True

            # 2. ¿El endpoint o cuerpo contiene palabras clave de IA?
            if tiene_palabra_ia_url or tiene_palabra_ia_body:
                score += 0.20

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

        if not candidatos or candidatos[0][0] < 0.35:
            logger.info("No se encontró ningún candidato HTTP con suficiente confianza.")
            return None

        mejor_score, mejor_obs = candidatos[0]
        return cls.construir_canal_desde_observacion(mejor_obs, marcador)

