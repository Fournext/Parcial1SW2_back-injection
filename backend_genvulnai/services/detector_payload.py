"""
Servicio para la inspección y localización recursiva del marcador en payloads.
Identifica la ruta exacta (JSON path, form-data o texto plano) donde viaja el prompt.
"""
import json
import logging
from urllib.parse import parse_qs
from typing import Any, Optional, Tuple, Dict, List
from backend_genvulnai.domain.enums import ModoEntrada
from backend_genvulnai.domain.schemas import ResultadoPayload

logger = logging.getLogger('backend_genvulnai')


class DetectorPayloadService:
    """Inspecciona cuerpos de peticiones HTTP para hallar la ubicación del prompt."""

    @classmethod
    def analizar_payload(cls, body: str, marcador: str, content_type: str = "") -> ResultadoPayload:
        """
        Analiza el cuerpo de la petición según su Content-Type y busca el marcador.
        Retorna ResultadoPayload con la ruta exacta y modo de entrada.
        """
        if not body or not marcador:
            return ResultadoPayload(
                contiene_marcador=False,
                campo_prompt=None,
                estructura_detectada=None,
                content_type=content_type,
                modo_entrada=cls._clasificar_modo_entrada(content_type)
            )

        content_type_lower = content_type.lower()

        # 1. Caso JSON (el más común en APIs de IA)
        if 'application/json' in content_type_lower or (body.strip().startswith('{') or body.strip().startswith('[')):
            try:
                datos_json = json.loads(body)
                ruta_encontrada = cls.buscar_marcador_recursivo(datos_json, marcador)
                if ruta_encontrada:
                    return ResultadoPayload(
                        contiene_marcador=True,
                        campo_prompt=ruta_encontrada,
                        estructura_detectada=datos_json,
                        content_type='application/json',
                        modo_entrada=ModoEntrada.TEXTO
                    )
            except Exception as err:
                logger.debug(f"El body no pudo ser parseado como JSON: {err}")

        # 2. Caso Form-urlencoded (formularios web tradicionales)
        if 'application/x-www-form-urlencoded' in content_type_lower or ('=' in body and marcador in body):
            try:
                dict_form = parse_qs(body)
                for clave, valores in dict_form.items():
                    for valor in valores:
                        if marcador in valor:
                            return ResultadoPayload(
                                contiene_marcador=True,
                                campo_prompt=clave,
                                estructura_detectada=dict_form,
                                content_type='application/x-www-form-urlencoded',
                                modo_entrada=ModoEntrada.TEXTO
                            )
            except Exception:
                pass

        # 3. Caso Multipart/Form-data (subida de archivos o texto mixto)
        if 'multipart/form-data' in content_type_lower:
            campo = cls._buscar_en_multipart(body, marcador)
            modo = ModoEntrada.MIXTO if 'filename=' in body else ModoEntrada.TEXTO
            return ResultadoPayload(
                contiene_marcador=marcador in body,
                campo_prompt=campo,
                estructura_detectada="multipart",
                content_type='multipart/form-data',
                modo_entrada=modo
            )

        # 4. Caso Texto plano u otro
        if marcador in body:
            return ResultadoPayload(
                contiene_marcador=True,
                campo_prompt="raw_body",
                estructura_detectada="raw_text",
                content_type=content_type or 'text/plain',
                modo_entrada=ModoEntrada.TEXTO
            )

        return ResultadoPayload(
            contiene_marcador=False,
            campo_prompt=None,
            estructura_detectada=None,
            content_type=content_type,
            modo_entrada=cls._clasificar_modo_entrada(content_type)
        )

    @classmethod
    def buscar_marcador_recursivo(cls, estructura: Any, marcador: str, ruta_actual: str = "") -> Optional[str]:
        """
        Recorre recursivamente diccionarios y listas buscando la cadena del marcador.
        Retorna la ruta en notación de objeto (ej. 'conversation.messages[0].content').
        """
        if estructura is None:
            return None

        # Si es diccionario
        if isinstance(estructura, dict):
            for clave, valor in estructura.items():
                nueva_ruta = f"{ruta_actual}.{clave}" if ruta_actual else str(clave)
                resultado = cls.buscar_marcador_recursivo(valor, marcador, nueva_ruta)
                if resultado:
                    return resultado

        # Si es lista o tupla
        elif isinstance(estructura, (list, tuple)):
            for indice, elemento in enumerate(estructura):
                nueva_ruta = f"{ruta_actual}[{indice}]"
                resultado = cls.buscar_marcador_recursivo(elemento, marcador, nueva_ruta)
                if resultado:
                    return resultado

        # Si es string u otro valor primitivo
        elif isinstance(estructura, str):
            if marcador in estructura:
                return ruta_actual

        elif str(estructura) == marcador:
            return ruta_actual

        return None

    @classmethod
    def _buscar_en_multipart(cls, body: str, marcador: str) -> Optional[str]:
        """Busca el nombre del campo en una carga multipart."""
        import re
        patron = r'name="([^"]+)"[\r\n]+(?:\r\n)?(.*?)(?=--|\Z)'
        matches = re.findall(patron, body, re.DOTALL)
        for nombre, contenido in matches:
            if marcador in contenido:
                return nombre
        return None

    @classmethod
    def _clasificar_modo_entrada(cls, content_type: str) -> str:
        """Clasifica el modo de entrada según el MIME type del request."""
        ct = content_type.lower()
        if any(audio in ct for audio in ['audio/webm', 'audio/wav', 'audio/mpeg', 'audio/ogg']):
            return ModoEntrada.AUDIO
        if 'application/pdf' in ct or 'application/octet-stream' in ct:
            return ModoEntrada.ARCHIVO
        if 'multipart/' in ct:
            return ModoEntrada.MULTIPART
        if any(txt in ct for txt in ['application/json', 'text/', 'application/x-www-form-urlencoded']):
            return ModoEntrada.TEXTO
        return ModoEntrada.DESCONOCIDO
