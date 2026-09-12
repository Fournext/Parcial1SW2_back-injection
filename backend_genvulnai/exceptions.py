"""
Excepciones de dominio y servicios para backend_genvulnai.
"""

class DescubrimientoError(Exception):
    """Excepción base para fallos en el proceso de descubrimiento."""
    pass


class URLNoPermitidaError(DescubrimientoError):
    """Lanzada cuando la URL solicitada no cumple con la política de seguridad o lista blanca."""
    pass


class NavegacionError(DescubrimientoError):
    """Lanzada cuando el navegador automatizado no logra acceder al objetivo."""
    pass


class InterfazNoEncontradaError(DescubrimientoError):
    """Lanzada cuando no se logra identificar ningún campo de entrada para interactuar."""
    pass


class CanalNoDetectadoError(DescubrimientoError):
    """Lanzada cuando no se encuentra ninguna petición asociada al envío del marcador."""
    pass


class EscaneoTimeoutError(DescubrimientoError):
    """Lanzada cuando el proceso excede el tiempo límite establecido."""
    pass
