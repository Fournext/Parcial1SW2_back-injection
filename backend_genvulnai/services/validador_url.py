"""
Servicio para validación estricta de URLs de destino y mitigación de SSRF.
Permite únicamente esquemas seguros y restringe el acceso a la lista autorizada de hosts.
"""
import ipaddress
import socket
from urllib.parse import urlparse
from typing import List, Tuple
from django.conf import settings
from backend_genvulnai.domain.constants import ESQUEMAS_PERMITIDOS
from backend_genvulnai.exceptions import URLNoPermitidaError


class ValidadorURLService:
    """Valida que los objetivos de escaneo cumplan estrictamente con las políticas de seguridad."""

    @classmethod
    def obtener_hosts_permitidos(cls) -> List[str]:
        """
        Obtiene la lista consolidada de URLs y hosts autorizados desde settings y base de datos.
        Lee ALLOWED_TARGET_URLS y ALLOWED_TARGET_HOSTS de settings y suma los registros de AllowedTargetURL (activa=True).
        """
        entradas: List[str] = []
        for clave in ('ALLOWED_TARGET_URLS', 'ALLOWED_TARGET_HOSTS'):
            valor = getattr(settings, clave, [])
            if isinstance(valor, str):
                entradas.extend([item.strip() for item in valor.split(',') if item.strip()])
            elif isinstance(valor, (list, tuple, set)):
                entradas.extend([str(item).strip() for item in valor if str(item).strip()])

        # Consultar objetivos autorizados dinámicamente en la base de datos
        try:
            from backend_genvulnai.models import AllowedTargetURL
            db_urls = AllowedTargetURL.objects.filter(activa=True).values_list('url', flat=True)
            for item in db_urls:
                if item and str(item).strip():
                    entradas.append(str(item).strip())
        except Exception:
            # En caso de que la tabla aún no exista o haya problemas de conexión
            pass

        if not entradas:
            entradas = ['localhost', '127.0.0.1']

        return [e.lower() for e in entradas]


    @classmethod
    def validar_url(cls, url: str) -> Tuple[bool, str]:
        """
        Valida exhaustivamente una URL de destino.
        Permite coincidencia por hostname, por 'hostname:puerto' o por prefijo de URL completa.
        Retorna (True, url_normalizada) o lanza URLNoPermitidaError.
        """
        if not url or not isinstance(url, str):
            raise URLNoPermitidaError("La URL proporcionada no es válida o está vacía.")

        url_limpia = url.strip()

        # Parsear componentes
        try:
            parsed = urlparse(url_limpia)
        except Exception as err:
            raise URLNoPermitidaError(f"Error al analizar la estructura de la URL: {err}")

        # 1. Validar esquema
        if not parsed.scheme or parsed.scheme.lower() not in ESQUEMAS_PERMITIDOS:
            raise URLNoPermitidaError(
                f"Esquema '{parsed.scheme}' no permitido. Solo se autorizan: {', '.join(ESQUEMAS_PERMITIDOS)}"
            )

        # 2. Validar hostname
        hostname = parsed.hostname
        if not hostname:
            raise URLNoPermitidaError("La URL no contiene un nombre de host o dominio válido.")

        hostname = hostname.lower()
        hosts_permitidos = cls.obtener_hosts_permitidos()

        # Comprobar comodín '*' para autorizar cualquier destino en laboratorios de prueba
        if '*' in hosts_permitidos:
            return True, url_limpia

        # A. Coincidencia directa por hostname (ej. 'localhost', '127.0.0.1', 'mi-ia.local')
        if hostname in hosts_permitidos:
            return True, url_limpia

        # B. Coincidencia por 'hostname:puerto' (ej. 'localhost:3000' o '127.0.0.1:8080')
        netloc = parsed.netloc.lower()
        if netloc in hosts_permitidos:
            return True, url_limpia

        # C. Coincidencia si la lista de .env contiene URLs completas (ej. 'http://localhost:3000')
        url_lower = url_limpia.lower()
        for entrada in hosts_permitidos:
            if entrada.startswith(('http://', 'https://')):
                entrada_sin_slash = entrada.rstrip('/')
                # Si la URL solicitada coincide exactamente o es un sub-recurso de la URL autorizada
                if url_lower.rstrip('/') == entrada_sin_slash or url_lower.startswith(f"{entrada_sin_slash}/"):
                    return True, url_limpia
                # También extraer el host de la URL configurada por si se autorizó el host completo
                try:
                    p_entrada = urlparse(entrada)
                    if p_entrada.hostname and p_entrada.hostname.lower() == hostname:
                        # Si no se especificó puerto en la URL permitida o los puertos son idénticos
                        if not p_entrada.port or p_entrada.port == parsed.port:
                            return True, url_limpia
                except Exception:
                    pass

        # D. Comprobar si es una dirección IP privada / loopback y si se permiten rangos locales
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_loopback and any(h in hosts_permitidos for h in ('localhost', '127.0.0.1', '::1')):
                return True, url_limpia
        except ValueError:
            pass

        # Si no coincidió con ninguna entrada autorizada, denegar
        raise URLNoPermitidaError(
            f"El host '{hostname}' no está en la lista de objetivos autorizados: {hosts_permitidos}. "
            "El sistema solo puede interactuar con entornos expresamente aprobados en ALLOWED_TARGET_URLS o ALLOWED_TARGET_HOSTS."
        )

