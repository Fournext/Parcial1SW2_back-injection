"""
Servicio responsable del transporte HTTP y despacho de peticiones contra endpoints de IA objetivo (D1).
Maneja cookies de sesión del navegador Playwright, tokens CSRF, estructuración dinámica de payloads y extracción de respuestas.
"""
import re
import copy
import time
import json
import logging
from typing import Any, Dict, Optional
import httpx

from backend_genvulnai.domain.schemas import ConfiguracionTransporte, RespuestaD1
from backend_genvulnai.exceptions import TransporteError

logger = logging.getLogger('backend_genvulnai')


class EjecutorTransporte:
    """Ejecuta peticiones HTTP síncronas contra el endpoint objetivo de IA (D1)."""

    @classmethod
    def construir_payload(cls, campo_prompt: str, prompt: str, estructura_base: Optional[Any] = None) -> Any:
        """
        Construye o inyecta el prompt en la estructura JSON correspondiente según el campo_prompt detectado.
        Soporta notaciones simples ('prompt', 'mensaje') y compuestas ('messages[0].content', 'data.input.text').
        """
        if not campo_prompt:
            return {"prompt": prompt}

        # Si tenemos una estructura base de referencia, la clonamos para mantener otros campos
        if isinstance(estructura_base, dict):
            payload = copy.deepcopy(estructura_base)
            cls._inyectar_en_ruta(payload, campo_prompt, prompt)
            return payload
        elif isinstance(estructura_base, list):
            payload = copy.deepcopy(estructura_base)
            cls._inyectar_en_ruta(payload, campo_prompt, prompt)
            return payload

        # Si no hay estructura base, construimos desde cero
        return cls._crear_estructura_desde_ruta(campo_prompt, prompt)

    @classmethod
    def _crear_estructura_desde_ruta(cls, ruta: str, valor: str) -> Any:
        """Crea recursivamente diccionarios y listas a partir de una ruta como 'messages[0].content'."""
        partes = cls._parsear_ruta(ruta)
        if not partes:
            return {ruta: valor}

        # Construir desde el fondo hacia afuera
        actual: Any = valor
        for p in reversed(partes):
            if isinstance(p, int):
                # Es un índice de lista
                nueva_lista = [None] * (p + 1)
                nueva_lista[p] = actual
                actual = nueva_lista
            else:
                actual = {p: actual}
        return actual

    @classmethod
    def _inyectar_en_ruta(cls, obj: Any, ruta: str, valor: str) -> None:
        """Modifica in-place un objeto dict o list navegando por la ruta dada."""
        partes = cls._parsear_ruta(ruta)
        if not partes:
            if isinstance(obj, dict):
                obj[ruta] = valor
            return

        cursor = obj
        for i, p in enumerate(partes[:-1]):
            siguiente_es_indice = isinstance(partes[i + 1], int)
            if isinstance(p, int):
                while len(cursor) <= p:
                    cursor.append({} if not siguiente_es_indice else [])
                cursor = cursor[p]
            else:
                if p not in cursor or not isinstance(cursor[p], (dict, list)):
                    cursor[p] = [] if siguiente_es_indice else {}
                cursor = cursor[p]

        ultima_parte = partes[-1]
        if isinstance(ultima_parte, int):
            while len(cursor) <= ultima_parte:
                cursor.append(None)
            cursor[ultima_parte] = valor
        else:
            if isinstance(cursor, dict):
                cursor[ultima_parte] = valor

    @classmethod
    def _parsear_ruta(cls, ruta: str) -> list:
        """
        Descompone 'messages[0].content' en ['messages', 0, 'content'].
        """
        tokens = []
        partes_punto = ruta.split('.')
        for seg in partes_punto:
            subpartes = re.split(r'\[(\d+)\]', seg)
            for sub in subpartes:
                if not sub:
                    continue
                if sub.isdigit():
                    tokens.append(int(sub))
                else:
                    tokens.append(sub)
        return tokens

    @classmethod
    def extraer_texto_respuesta(cls, response: httpx.Response) -> str:
        """
        Extrae el contenido conversacional relevante de la respuesta HTTP,
        manejando JSON, Streams SSE y texto plano.
        """
        content_type = response.headers.get("content-type", "").lower()

        # Caso 1: Server-Sent Events (SSE)
        if "text/event-stream" in content_type:
            lineas = response.text.splitlines()
            fragmentos = []
            for linea in lineas:
                linea_limpia = linea.strip()
                if linea_limpia.startswith("data:"):
                    contenido = linea_limpia[5:].strip()
                    if contenido == "[DONE]":
                        break
                    try:
                        data_json = json.loads(contenido)
                        fragmentos.append(cls._extraer_de_dict(data_json))
                    except Exception:
                        fragmentos.append(contenido)
            return "".join(fragmentos).strip() or response.text

        # Caso 2: JSON
        if "application/json" in content_type or response.text.strip().startswith(("{", "[")):
            try:
                data = response.json()
                if isinstance(data, dict):
                    return cls._extraer_de_dict(data)
                elif isinstance(data, list):
                    return "\n".join([cls._extraer_de_dict(item) if isinstance(item, dict) else str(item) for item in data])
            except Exception:
                pass

        # Caso 3: Fallback texto plano o HTML
        return response.text

    @classmethod
    def _extraer_de_dict(cls, data: Dict[str, Any]) -> str:
        """Busca claves habituales de respuesta de LLMs/Chatbots en un diccionario."""
        # Estructura tipo OpenAI: choices[0].message.content o choices[0].text
        if "choices" in data and isinstance(data["choices"], list) and len(data["choices"]) > 0:
            primera = data["choices"][0]
            if isinstance(primera, dict):
                if "message" in primera and isinstance(primera["message"], dict):
                    return str(primera["message"].get("content", ""))
                if "text" in primera:
                    return str(primera["text"])

        # Claves directas comunes en APIs de asistentes y chatbots
        claves_comunes = [
            "response", "reply", "respuesta", "mensaje", "message",
            "content", "text", "output", "diagram", "diagrama", "code",
            "generated_text", "result", "answer"
        ]
        for clave in claves_comunes:
            if clave in data and isinstance(data[clave], (str, int, float, bool)):
                return str(data[clave])

        # Si el backend objetivo encapsuló la respuesta directa del LLM en 'raw' (ej. fallo de JSON en Gemini con texto crudo)
        if "raw" in data and isinstance(data["raw"], str) and data["raw"].strip():
            return str(data["raw"]).strip()

        # Si ninguna clave coincide, devolver dump JSON
        return json.dumps(data, ensure_ascii=False)

    @classmethod
    def enviar(cls, config: ConfiguracionTransporte, prompt: str) -> RespuestaD1:
        """
        Envía una petición al endpoint D1 configurado, adjuntando cookies de sesión y headers adecuados.
        """
        # Preparar cabeceras
        headers_envio = {k: v for k, v in config.headers.items() if k.lower() not in ("host", "content-length", "connection")}
        
        # Inyectar CSRF token en headers si existe en cookies y no está presente
        if "csrftoken" in config.cookies and "x-csrftoken" not in [k.lower() for k in headers_envio]:
            headers_envio["X-CSRFToken"] = config.cookies["csrftoken"]
        elif "csrf_token" in config.cookies and "x-csrf-token" not in [k.lower() for k in headers_envio]:
            headers_envio["X-CSRF-Token"] = config.cookies["csrf_token"]

        metodo_upper = config.metodo.upper()
        url = config.url
        t_inicio = time.perf_counter()

        try:
            with httpx.Client(
                cookies=config.cookies,
                verify=False,
                timeout=config.timeout_seconds,
                follow_redirects=True
            ) as client:
                if metodo_upper == "GET":
                    params = {config.campo_prompt: prompt}
                    resp = client.get(url, params=params, headers=headers_envio)
                else:
                    is_form = "form" in config.content_type.lower()
                    if is_form:
                        form_data = {config.campo_prompt: prompt}
                        headers_envio["Content-Type"] = "application/x-www-form-urlencoded"
                        resp = client.request(metodo_upper, url, data=form_data, headers=headers_envio)
                    else:
                        headers_envio["Content-Type"] = "application/json"
                        cuerpo = cls.construir_payload(config.campo_prompt, prompt, config.estructura_cuerpo)
                        resp = client.request(metodo_upper, url, json=cuerpo, headers=headers_envio)

            latencia = (time.perf_counter() - t_inicio) * 1000.0
            texto_extraido = cls.extraer_texto_respuesta(resp)
            headers_resp = dict(resp.headers)

            return RespuestaD1(
                texto=texto_extraido,
                status_code=resp.status_code,
                latencia_ms=round(latencia, 2),
                headers=headers_resp,
                error=None if resp.is_success else f"HTTP {resp.status_code}: {resp.reason_phrase}"
            )

        except httpx.TimeoutException as ex:
            latencia = (time.perf_counter() - t_inicio) * 1000.0
            msg = f"Timeout al contactar D1 tras {config.timeout_seconds}s: {ex}"
            logger.warning(msg)
            return RespuestaD1(texto="", status_code=408, latencia_ms=round(latencia, 2), error=msg)

        except httpx.ConnectError as ex:
            latencia = (time.perf_counter() - t_inicio) * 1000.0
            msg = f"Error de conexión con el endpoint D1 ({url}): {ex}"
            logger.error(msg)
            return RespuestaD1(texto="", status_code=503, latencia_ms=round(latencia, 2), error=msg)

        except Exception as ex:
            latencia = (time.perf_counter() - t_inicio) * 1000.0
            msg = f"Error inesperado en transporte contra D1: {ex}"
            logger.error(msg, exc_info=True)
            return RespuestaD1(texto="", status_code=500, latencia_ms=round(latencia, 2), error=msg)
