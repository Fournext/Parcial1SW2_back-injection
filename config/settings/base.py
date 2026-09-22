"""
Configuración base para el proyecto de descubrimiento de canales de IA.
"""
from pathlib import Path
import os
import environ
import dj_database_url

# Directorio raíz del proyecto
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Inicializar environ
env = environ.Env()

# Leer .env si existe
env_file = BASE_DIR / '.env'
if env_file.exists():
    environ.Env.read_env(env_file)

# Configuración de Seguridad
SECRET_KEY = env('SECRET_KEY', default='django-insecure-default-key-change-me')
DEBUG = env.bool('DEBUG', default=True)
ALLOWED_HOSTS = env.list('ALLOWED_HOSTS', default=['*'])

# Aplicaciones Instaladas
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # Terceros
    'rest_framework',
    
    # Aplicación principal del dominio
    'backend_genvulnai.apps.BackendGenvulnaiConfig',
]

# Middlewares
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'
ASGI_APPLICATION = 'config.asgi.application'

# Base de datos: PostgreSQL obligatorio
DB_NAME = env('DB_NAME', default=None)

if DB_NAME:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': DB_NAME,
            'USER': env('DB_USER', default='postgres'),
            'PASSWORD': env('DB_PASSWORD', default='postgres'),
            'HOST': env('DB_HOST', default='localhost'),
            'PORT': env('DB_PORT', default='5432'),
            'CONN_MAX_AGE': 600,
            'CONN_HEALTH_CHECKS': True,
        }
    }
else:
    DATABASE_URL = env(
        'DATABASE_URL', 
        default='postgresql://postgres:postgres@localhost:5432/db_genvulnai'
    )
    DATABASES = {
        'default': dj_database_url.parse(
            DATABASE_URL,
            conn_max_age=600,
            conn_health_checks=True
        )
    }


# Validadores de contraseñas
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# Internacionalización
LANGUAGE_CODE = 'es-es'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Archivos estáticos
STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Django REST Framework
REST_FRAMEWORK = {
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer',
    ],
    'DEFAULT_PARSER_CLASSES': [
        'rest_framework.parsers.JSONParser',
        'rest_framework.parsers.FormParser',
        'rest_framework.parsers.MultiPartParser',
    ],
    'EXCEPTION_HANDLER': 'rest_framework.views.exception_handler',
}

# Configuración personalizada de Descubrimiento de IA y Seguridad
ALLOWED_TARGET_HOSTS = env.list(
    'ALLOWED_TARGET_HOSTS', 
    default=['localhost', '127.0.0.1', 'devtunnels.ms', '*.devtunnels.ms', '*']
)
ALLOWED_TARGET_URLS = env.list(
    'ALLOWED_TARGET_URLS',
    default=[]
)


PLAYWRIGHT_HEADLESS = env.bool('PLAYWRIGHT_HEADLESS', default=True)
DISCOVERY_TIMEOUT_SECONDS = env.int('DISCOVERY_TIMEOUT_SECONDS', default=30)
MAX_CAPTURED_REQUESTS = env.int('MAX_CAPTURED_REQUESTS', default=500)
MAX_BODY_BYTES = env.int('MAX_BODY_BYTES', default=51200)

# Explorador Activo del DOM
MAX_EXPLORATION_STEPS = env.int('MAX_EXPLORATION_STEPS', default=25)
MAX_EXPLORATION_DEPTH = env.int('MAX_EXPLORATION_DEPTH', default=3)
EXPLORATION_WAIT_MS = env.int('EXPLORATION_WAIT_MS', default=2000)

# Configuración de Ollama (IA Semántica Local)
OLLAMA = {
    'ENABLED': env.bool('OLLAMA_ENABLED', default=True),
    'BASE_URL': env('OLLAMA_BASE_URL', default='http://localhost:11434'),
    'MODEL': env('OLLAMA_MODEL', default='hf.co/QuantFactory/Hermes-3-Llama-3.1-8B-lorablated-GGUF:Q4_K_S'),
    'TIMEOUT_SECONDS': env.float('OLLAMA_TIMEOUT_SECONDS', default=60.0),
    'TEMPERATURE': env.float('OLLAMA_TEMPERATURE', default=0.1),
    'MAX_RETRIES': env.int('OLLAMA_MAX_RETRIES', default=2),
    'MIN_HEURISTIC_CONFIDENCE': env.float('OLLAMA_MIN_HEURISTIC_CONFIDENCE', default=0.80),
}

# Configuración del Motor de Ataque y Evaluación
ATTACK_MAX_TURNS = env.int('ATTACK_MAX_TURNS', default=20)
ATTACK_RESET_CONSECUTIVE_FAILURES = env.int('ATTACK_RESET_CONSECUTIVE_FAILURES', default=3)
ATTACK_A1_MODEL = env('ATTACK_A1_MODEL', default=env('OLLAMA_MODEL', default='hf.co/QuantFactory/Hermes-3-Llama-3.1-8B-lorablated-GGUF:Q4_K_S'))
ATTACK_J1_MODEL = env('ATTACK_J1_MODEL', default='hf.co/unsloth/Qwen3.5-4B-GGUF:UD-Q4_K_XL')
ATTACK_A1_TEMPERATURE = env.float('ATTACK_A1_TEMPERATURE', default=0.7)
ATTACK_J1_TEMPERATURE = env.float('ATTACK_J1_TEMPERATURE', default=0.1)
ATTACK_D1_TIMEOUT_SECONDS = env.float('ATTACK_D1_TIMEOUT_SECONDS', default=120.0)
ATTACK_J1_MAX_TOKENS = env.int('ATTACK_J1_MAX_TOKENS', default=256)



# Logging estructurado del sistema
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'estructurado': {
            'format': '[%(asctime)s] [%(levelname)s] [%(name)s] [%(funcName)s]: %(message)s',
            'datefmt': '%Y-%m-%d %H:%M:%S',
        },
    },
    'handlers': {
        'consola': {
            'class': 'logging.StreamHandler',
            'formatter': 'estructurado',
        },
    },
    'loggers': {
        'backend_genvulnai': {
            'handlers': ['consola'],
            'level': 'INFO',
            'propagate': False,
        },
        'django': {
            'handlers': ['consola'],
            'level': 'WARNING',
            'propagate': False,
        },
    },
}
