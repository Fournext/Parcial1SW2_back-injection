"""
Servicio para la detección de mecanismos de autenticación utilizados en las solicitudes.
Identifica esquemas (Bearer, Cookies, CSRF, API-Key) sin retener ningún valor confidencial.
"""
from typing import Dict, List
from backend_genvulnai.domain.enums import TipoAutenticacion
from backend_genvulnai.domain.schemas import ResultadoAutenticacion
from backend_genvulnai.services.sanitizador import SanitizadorService


class DetectorAutenticacionService:
    """Inspecciona cabeceras sanitizadas para catalogar el esquema de autenticación."""

    @classmethod
    def analizar_autenticacion(cls, headers: Dict[str, str]) -> ResultadoAutenticacion:
        """
        Evalúa las cabeceras HTTP de la petición candidata.
        Retorna los tipos detectados, nombres de cookies y nombres de headers.
        """
        tipos_detectados: List[str] = []
        cookies_encontradas: List[str] = []
        headers_encontrados: List[str] = []

        if not headers:
            return ResultadoAutenticacion(
                requerida=False,
                tipos=[],
                cookies=[],
                headers=[]
            )

        headers_lower = {k.lower(): (k, str(v)) for k, v in headers.items()}

        # 1. Bearer Token y Basic Auth en Authorization
        if 'authorization' in headers_lower:
            orig_key, valor = headers_lower['authorization']
            headers_encontrados.append(orig_key)
            valor_lower = valor.lower().strip()
            if valor_lower.startswith('bearer'):
                tipos_detectados.append(TipoAutenticacion.BEARER_TOKEN)
            elif valor_lower.startswith('basic'):
                tipos_detectados.append(TipoAutenticacion.BASIC)
            else:
                tipos_detectados.append(TipoAutenticacion.DESCONOCIDA)

        # 2. Cookies de sesión
        if 'cookie' in headers_lower:
            orig_key, valor = headers_lower['cookie']
            nombres = SanitizadorService.extraer_nombres_cookies(valor)
            if nombres:
                cookies_encontradas.extend(nombres)
                headers_encontrados.append(orig_key)
                
                # Identificar si hay cookies asociadas a sesión o CSRF
                tiene_sesion = any(c in ('sessionid', 'jsessionid', 'connect.sid', 'phpsessid', 'session') for c in [n.lower() for n in nombres])
                tiene_csrf_cookie = any('csrf' in c.lower() for c in nombres)

                if tiene_sesion:
                    tipos_detectados.append(TipoAutenticacion.COOKIE_SESSION)
                if tiene_csrf_cookie and TipoAutenticacion.CSRF not in tipos_detectados:
                    tipos_detectados.append(TipoAutenticacion.CSRF)
                
                if not tiene_sesion and not tiene_csrf_cookie and nombres:
                    tipos_detectados.append(TipoAutenticacion.COOKIE_SESSION)

        # 3. Encabezados CSRF explícitos
        for csrf_header in ['x-csrftoken', 'x-csrf-token', 'csrf-token']:
            if csrf_header in headers_lower:
                orig_key, _ = headers_lower[csrf_header]
                headers_encontrados.append(orig_key)
                if TipoAutenticacion.CSRF not in tipos_detectados:
                    tipos_detectados.append(TipoAutenticacion.CSRF)

        # 4. API Keys en headers personalizados
        for key_header in ['x-api-key', 'api-key', 'apikey', 'x-openai-api-key']:
            if key_header in headers_lower:
                orig_key, _ = headers_lower[key_header]
                headers_encontrados.append(orig_key)
                if TipoAutenticacion.API_KEY not in tipos_detectados:
                    tipos_detectados.append(TipoAutenticacion.API_KEY)

        # Deduplicar listas preservando orden
        tipos_unicos = list(dict.fromkeys(tipos_detectados))
        headers_unicos = list(dict.fromkeys(headers_encontrados))
        cookies_unicas = list(dict.fromkeys(cookies_encontradas))

        es_requerida = len(tipos_unicos) > 0

        return ResultadoAutenticacion(
            requerida=es_requerida,
            tipos=tipos_unicos,
            cookies=cookies_unicas,
            headers=headers_unicos
        )
