"""
Servicio responsable de la sanitización de cabeceras, cookies y cuerpos de red.
Garantiza que nunca se persistan ni emitan credenciales o tokens en texto plano.
"""
import re
from typing import Dict, List, Any
from backend_genvulnai.domain.constants import HEADERS_SENSIBLES, LIMITE_BODY_BYTES_DEFAULT


class SanitizadorService:
    """Provee métodos estáticos y utilitarios para sanitizar datos sensibles."""

    VALOR_REDACTADO = "[REDACTADO]"

    @classmethod
    def sanitizar_headers(cls, headers: Dict[str, Any]) -> Dict[str, str]:
        """
        Sanitiza las cabeceras HTTP enmascarando tokens de autorización,
        cookies y claves API sensibles.
        """
        if not headers:
            return {}

        headers_limpios: Dict[str, str] = {}
        for clave, valor in headers.items():
            clave_lower = str(clave).lower().strip()
            valor_str = str(valor)

            if clave_lower in HEADERS_SENSIBLES:
                if clave_lower == 'authorization':
                    # Preservar el esquema (ej. Bearer, Basic) si está presente
                    partes = valor_str.split(' ', 1)
                    if len(partes) > 1:
                        headers_limpios[clave] = f"{partes[0]} {cls.VALOR_REDACTADO}"
                    else:
                        headers_limpios[clave] = cls.VALOR_REDACTADO
                elif clave_lower in ('cookie', 'set-cookie'):
                    # Retener nombres de cookies pero redactar sus valores
                    headers_limpios[clave] = cls.sanitizar_cadena_cookie(valor_str)
                else:
                    headers_limpios[clave] = cls.VALOR_REDACTADO
            else:
                headers_limpios[clave] = valor_str

        return headers_limpios

    @classmethod
    def sanitizar_cadena_cookie(cls, cookie_str: str) -> str:
        """
        Dada una cadena de cookies (ej. 'sessionid=xyz; csrftoken=abc'),
        retorna los nombres preservados pero los valores redactados.
        """
        if not cookie_str:
            return ""

        partes = cookie_str.split(';')
        cookies_sanitizadas = []
        for parte in partes:
            if '=' in parte:
                nombre, _ = parte.split('=', 1)
                cookies_sanitizadas.append(f"{nombre.strip()}={cls.VALOR_REDACTADO}")
            else:
                cookies_sanitizadas.append(parte.strip())

        return "; ".join(cookies_sanitizadas)

    @classmethod
    def extraer_nombres_cookies(cls, cookie_header: str) -> List[str]:
        """
        Extrae únicamente los nombres de las cookies presentes en una cabecera.
        """
        if not cookie_header:
            return []

        nombres: List[str] = []
        for fragmento in cookie_header.split(';'):
            fragmento = fragmento.strip()
            if '=' in fragmento:
                nombre = fragmento.split('=', 1)[0].strip()
                if nombre and nombre not in nombres:
                    nombres.append(nombre)
        return nombres

    @classmethod
    def truncar_y_sanitizar_body(cls, body: str, limite: int = LIMITE_BODY_BYTES_DEFAULT) -> str:
        """
        Trunca el cuerpo para no saturar la base de datos y oculta posibles
        patrones de contraseñas o tokens embebidos.
        """
        if not body:
            return ""

        texto = str(body)
        if len(texto.encode('utf-8')) > limite:
            texto = texto[:limite] + "... [TRUNCADO POR TAMAÑO]"

        # Redactar posibles contraseñas en formatos JSON o form-data
        patron_password = r'("(?:password|passwd|token|secret|access_token)"\s*:\s*)"[^"]+"'
        texto = re.sub(patron_password, rf'\1"{cls.VALOR_REDACTADO}"', texto, flags=re.IGNORECASE)

        return texto
