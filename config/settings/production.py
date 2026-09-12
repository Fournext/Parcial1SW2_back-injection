"""
Configuración de producción.
"""
from config.settings.base import *

DEBUG = False

# En producción exigir hosts explícitos y cookies seguras
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True

LOGGING['loggers']['backend_genvulnai']['level'] = 'INFO'
