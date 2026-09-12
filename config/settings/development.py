"""
Configuración de desarrollo.
"""
from config.settings.base import *

DEBUG = True

ALLOWED_HOSTS = ['*']

LOGGING['loggers']['backend_genvulnai']['level'] = 'DEBUG'
