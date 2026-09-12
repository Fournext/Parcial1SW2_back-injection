"""
Selector de configuración dinámica según la variable de entorno DJANGO_ENV.
"""
import os

env_name = os.getenv("DJANGO_ENV", "development").lower()

if env_name == "production":
    from config.settings.production import *
else:
    from config.settings.development import *
