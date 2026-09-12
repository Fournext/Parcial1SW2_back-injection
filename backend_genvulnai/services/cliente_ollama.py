"""
Cliente HTTP síncrono para interactuar con la API REST de Ollama.
"""
import json
import logging
import re
from typing import Any, Dict, List, Optional
from django.conf import settings
import httpx

from backend_genvulnai.domain.constants import EventosLog
from backend_genvulnai.domain.schemas import EstadoOllama

logger = logging.getLogger('backend_genvulnai')


class ClienteOllama:
    """
    Cliente para comunicación HTTP síncrona con el servicio local de Ollama.
    Diseñado para fallar de forma segura sin bloquear el flujo principal de la aplicación.
    """

    def __init__(self, configuracion: Optional[Dict[str, Any]] = None):
        cfg = configuracion or getattr(settings, 'OLLAMA', {})
        self.habilitado: bool = cfg.get('ENABLED', True)
        self.base_url: str = cfg.get('BASE_URL', 'http://localhost:11434').rstrip('/')
        self.modelo: str = cfg.get('MODEL', 'llama3.2')
        self.timeout: float = float(cfg.get('TIMEOUT_SECONDS', 15.0))
        self.temperature: float = float(cfg.get('TEMPERATURE', 0.1))
        self.max_retries: int = int(cfg.get('MAX_RETRIES', 2))

    def _crear_cliente(self) -> httpx.Client:
        """Crea una instancia configurada de httpx.Client síncrono."""
        return httpx.Client(
            base_url=self.base_url,
            timeout=self.timeout
        )

    def consultar_estado(self) -> EstadoOllama:
        """
        Consulta la disponibilidad del servidor de Ollama y la lista de modelos instalados.

        Returns:
            Instancia de EstadoOllama reflejando la disponibilidad y modelos.
        """
        if not self.habilitado:
            return EstadoOllama(
                disponible=False,
                modelos_disponibles=[],
                modelo_configurado=self.modelo,
                modelo_presente=False,
                error="Ollama está deshabilitado en la configuración."
            )

        url = f"{self.base_url}/api/tags"
        try:
            with self._crear_cliente() as client:
                respuesta = client.get("/api/tags")
                respuesta.raise_for_status()
                data = respuesta.json()
                
                modelos = [m.get('name', '') for m in data.get('models', [])]
                # Coincidencia con o sin etiqueta de tag (ej. llama3.2 o llama3.2:latest)
                modelo_presente = any(
                    m == self.modelo or m.startswith(f"{self.modelo}:") 
                    for m in modelos
                )
                
                return EstadoOllama(
                    disponible=True,
                    modelos_disponibles=modelos,
                    modelo_configurado=self.modelo,
                    modelo_presente=modelo_presente,
                    error=None
                )
        except httpx.ConnectError:
            msg = f"No se pudo conectar a Ollama en {self.base_url}. ¿Está el servicio ejecutándose?"
            logger.warning(f"[{EventosLog.OLLAMA_CALL_FAILED}] {msg}")
            return EstadoOllama(
                disponible=False,
                modelos_disponibles=[],
                modelo_configurado=self.modelo,
                modelo_presente=False,
                error=msg
            )
        except httpx.TimeoutException:
            msg = f"Tiempo de espera agotado al conectar a Ollama ({self.timeout}s)."
            logger.warning(f"[{EventosLog.OLLAMA_CALL_FAILED}] {msg}")
            return EstadoOllama(
                disponible=False,
                modelos_disponibles=[],
                modelo_configurado=self.modelo,
                modelo_presente=False,
                error=msg
            )
        except Exception as e:
            msg = f"Error al verificar estado de Ollama: {str(e)}"
            logger.warning(f"[{EventosLog.OLLAMA_CALL_FAILED}] {msg}")
            return EstadoOllama(
                disponible=False,
                modelos_disponibles=[],
                modelo_configurado=self.modelo,
                modelo_presente=False,
                error=msg
            )

    def chat(self, prompt_sistema: str, prompt_usuario: str) -> Optional[Dict[str, Any]]:
        """
        Envía una petición de chat estructurada al endpoint /api/chat de Ollama y parsea la respuesta JSON.

        Args:
            prompt_sistema: Instrucciones del sistema y formato estricto esperado.
            prompt_usuario: Contenido contextual del análisis a realizar.

        Returns:
            Diccionario parseado con la respuesta JSON del modelo, o None si ocurrió un error.
        """
        if not self.habilitado:
            logger.info(f"[{EventosLog.OLLAMA_SKIPPED_DISABLED}] Ollama está deshabilitado globalmente.")
            return None

        cuerpo_solicitud = {
            "model": self.modelo,
            "messages": [
                {"role": "system", "content": prompt_sistema},
                {"role": "user", "content": prompt_usuario}
            ],
            "stream": False,
            "format": "json",
            "options": {
                "temperature": self.temperature
            }
        }

        reintentos_restantes = self.max_retries
        ultimo_error: Optional[Exception] = None

        logger.info(
            f"[{EventosLog.OLLAMA_CALL_STARTED}] Enviando solicitud a Ollama modelo={self.modelo} base_url={self.base_url}"
        )

        while reintentos_restantes >= 0:
            try:
                with self._crear_cliente() as client:
                    respuesta = client.post("/api/chat", json=cuerpo_solicitud)
                    respuesta.raise_for_status()
                    datos_respuesta = respuesta.json()

                    contenido_texto = datos_respuesta.get('message', {}).get('content', '').strip()
                    logger.info(f"[{EventosLog.OLLAMA_CALL_SUCCESS}] Respuesta recibida de Ollama.")

                    # Extraer y parsear JSON limpio
                    json_parseado = self._extraer_json(contenido_texto)
                    if json_parseado is not None:
                        return json_parseado

                    logger.warning(
                        f"[{EventosLog.OLLAMA_JSON_PARSE_ERROR}] Contenido no parseable como JSON: {contenido_texto[:200]}"
                    )
                    return None

            except (httpx.ConnectError, httpx.TimeoutException) as exc:
                ultimo_error = exc
                reintentos_restantes -= 1
                if reintentos_restantes >= 0:
                    logger.warning(
                        f"[{EventosLog.OLLAMA_CALL_FAILED}] Reintentando conexión con Ollama ({reintentos_restantes} restantes): {str(exc)}"
                    )
            except Exception as exc:
                ultimo_error = exc
                logger.error(
                    f"[{EventosLog.OLLAMA_CALL_FAILED}] Error inesperado en llamada a Ollama: {str(exc)}"
                )
                break

        logger.warning(
            f"[{EventosLog.OLLAMA_FALLBACK_TRIGGERED}] Fallback activado tras fallo en Ollama: {str(ultimo_error)}"
        )
        return None

    def _extraer_json(self, texto: str) -> Optional[Dict[str, Any]]:
        """
        Extrae y deserializa un objeto JSON de una cadena de texto, manejando posibles bloques Markdown.

        Args:
            texto: Cadena de texto recibida del modelo.

        Returns:
            Diccionario parseado o None si no se puede deserializar.
        """
        if not texto:
            return None

        # Intentar parseo directo
        try:
            return json.loads(texto)
        except json.JSONDecodeError:
            pass

        # Remover bloques de código markdown ```json ... ``` o ``` ... ```
        patron_bloque = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', texto)
        if patron_bloque:
            try:
                return json.loads(patron_bloque.group(1))
            except json.JSONDecodeError:
                pass

        # Buscar llaves delimitadoras {...}
        inicio = texto.find('{')
        fin = texto.rfind('}')
        if inicio != -1 and fin != -1 and fin > inicio:
            try:
                return json.loads(texto[inicio:fin + 1])
            except json.JSONDecodeError:
                pass

        return None
