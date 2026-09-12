"""
Configuración de la aplicación backend_genvulnai.
"""
from django.apps import AppConfig


class BackendGenvulnaiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'backend_genvulnai'
    verbose_name = 'Descubrimiento de Canales de IA (GenVulnAI)'
