# Sistema de Descubrimiento de Canales de Inteligencia Artificial

Sistema integral y modular desarrollado en **Django**, **Django REST Framework** y **Playwright** que analiza de forma automatizada aplicaciones web locales o entornos de laboratorio autorizados para descubrir de qué manera envían entradas (prompts, mensajes, audios o archivos) hacia modelos o servicios de Inteligencia Artificial (IA).

---

## 1. Arquitectura y Principios de Diseño

El proyecto sigue principios de **Clean Architecture**, **SOLID** y separación estricta de responsabilidades:

- **Capa de Dominio (`backend_genvulnai/domain/`)**: Contiene las definiciones esenciales del problema: enumeraciones (`enums.py`), DTOs y schemas tipados (`schemas.py`) y constantes de seguridad (`constants.py`).
- **Capa de Servicios (`backend_genvulnai/services/`)**: Módulos desacoplados donde cada servicio atiende un único propósito:
  - `NavegadorService`: Gestión del ciclo de vida y contención de Playwright Chromium.
  - `CapturadorRedService`: Intercepta y registra tráfico HTTP y tramas de WebSocket.
  - `DescubridorInterfazService`: Heurística sobre el DOM para identificar selectores de entrada y botones de envío.
  - `SanitizadorService`: Enmascaramiento y eliminación de credenciales, cookies de sesión y tokens sensibles.
  - `ValidadorURLService`: Mitigación de SSRF y chequeo contra listas blancas.
  - `DetectorPayloadService`: Búsqueda recursiva en JSON anidados, multipart o form-urlencoded para aislar el campo del prompt.
  - `DetectorAutenticacionService`: Catalogación de esquemas de autenticación (Bearer, Cookies, CSRF, API-Key) sin almacenar secretos.
  - `DetectorWebSocketService`: Detección de marcadores en tramas WebSocket.
  - `DetectorStreamingService`: Detección de flujos SSE (`text/event-stream`) y chunked responses.
  - `CalculadorConfianzaService`: Ponderación numérica normalizada y combinación de confianza con IA.
  - `ClienteOllama`: Cliente HTTP síncrono (`httpx`) con reintentos y tolerancia a fallos para interactuar con Ollama.
  - `AnalizadorIA`: Capa de desambiguación semántica que analiza candidatos de DOM y tráfico HTTP.
  - `OrquestadorDescubrimientoService`: Coordinación secuencial y asíncrona de todas las fases.
- **Capa de Prompts (`backend_genvulnai/prompts/`)**: Plantillas centralizadas e independientes para guiar las inferencias del LLM local sin acoplamiento a servicios.
- **Capa de Persistencia (`backend_genvulnai/repositories/`)**: Encapsula las transacciones ORM para `DiscoveryScan`, `AIChannel` y `NetworkObservation`.
- **Capa de Presentación y API (`backend_genvulnai/views.py`, `serializers.py`, `urls.py`)**: Endpoints REST estructurados bajo Django REST Framework, incluyendo diagnóstico de salud de Ollama.

---

## 2. Requisitos Previos

- **Python 3.12+**
- **PostgreSQL 14+** (Obligatorio)
- **Navegador Chromium para Playwright**
- (Opcional) **Docker** y **Docker Compose**

---

## 3. Instalación Local Paso a Paso

### 3.1. Clonar el repositorio y preparar entorno virtual

```bash
# Navegar a la raíz del backend
cd backend

# Crear entorno virtual
python -m venv env

# Activar entorno virtual
# En Windows (PowerShell):
.\env\Scripts\Activate.ps1
# En Linux/macOS:
source env/bin/activate
```

### 3.2. Instalar dependencias Python

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 3.3. Instalar navegadores de Playwright

```bash
playwright install chromium
```

---

## 4. Configuración de PostgreSQL y Variables de Entorno

### 4.1. Crear la Base de Datos

En su consola de PostgreSQL o pgAdmin, asegúrese de tener la base de datos creada:

```sql
CREATE DATABASE ai_discovery;
```

### 4.2. Configurar el archivo `.env`

Copie la plantilla de ejemplo y configure su cadena de conexión:

```bash
cp .env.example .env
```

Edite `.env` con sus credenciales:

```env
DEBUG=True
SECRET_KEY=clave-secreta-de-desarrollo-local
DJANGO_ENV=development

# Configuración de PostgreSQL
DATABASE_URL=postgresql://postgres:su_password@localhost:5432/ai_discovery

# Lista blanca de hosts autorizados (mitigación SSRF)
ALLOWED_TARGET_HOSTS=localhost,127.0.0.1

# Playwright
PLAYWRIGHT_HEADLESS=True
DISCOVERY_TIMEOUT_SECONDS=30
MAX_CAPTURED_REQUESTS=500
```

---

## 5. Migraciones y Puesta en Marcha

```bash
# Crear y aplicar migraciones en PostgreSQL
python manage.py makemigrations backend_genvulnai
python manage.py migrate

# (Opcional) Crear superusuario para el panel de administración
python manage.py createsuperuser

# Iniciar el servidor de desarrollo
python manage.py runserver 0.0.0.0:8000
```

---

## 6. Ejecución con Docker Compose

Si prefiere ejecutar todo el entorno (PostgreSQL + Backend + Playwright) en contenedores:

```bash
docker-compose up --build
```

---

## 7. Ejecución de Pruebas Automatizadas

```bash
# Ejecutar todas las pruebas unitarias e integración de la API
pytest
```

Para ver la salida detallada:

```bash
pytest -v -s
```

---

## 8. Uso de la API REST

### 8.1. Iniciar un Escaneo de Descubrimiento

**Petición:**
```http
POST /api/descubrimientos/
Content-Type: application/json

{
  "url": "http://localhost:3000"
}
```

**Respuesta inicial (201 Created):**
```json
{
  "id": "e8b2c451-93c1-4b1c-99d8-9df24f114c0a",
  "target_url": "http://localhost:3000",
  "status": "pendiente",
  "mensaje": "Escaneo iniciado exitosamente. Consulte el estado en este mismo endpoint."
}
```

### 8.2. Consultar el Resultado del Escaneo

**Petición:**
```http
GET /api/descubrimientos/e8b2c451-93c1-4b1c-99d8-9df24f114c0a/
```

**Respuesta consolidada (200 OK):**
```json
{
  "id": "e8b2c451-93c1-4b1c-99d8-9df24f114c0a",
  "target_url": "http://localhost:3000",
  "status": "completado",
  "marcador": "DISCOVERY_TEST_a7f92c1b",
  "resultado": {
    "objetivo": {
      "url": "http://localhost:3000",
      "accesible": true
    },
    "interfaz": {
      "tipo": "chat",
      "selector_entrada": "textarea#prompt",
      "selector_envio": "button[type=submit]",
      "metodo_envio": "boton"
    },
    "canal": {
      "protocolo": "http",
      "transporte": "http",
      "url": "http://localhost:3000/api/chat",
      "metodo": "POST",
      "content_type": "application/json",
      "entrada": {
        "modo": "texto",
        "campo": "conversation.messages[0].content"
      },
      "respuesta": {
        "modo": "sse"
      }
    },
    "autenticacion": {
      "requerida": true,
      "tipos": [
        "cookie_session",
        "csrf"
      ],
      "cookies": [
        "sessionid"
      ],
      "headers": [
        "X-CSRFToken"
      ]
    },
    "confianza": 0.95,
    "marcador_utilizado": "DISCOVERY_TEST_a7f92c1b",
    "observaciones_registradas": 14
  },
  "error_message": null,
  "started_at": "2026-09-11T23:15:00Z",
  "finished_at": "2026-09-11T23:15:08Z",
  "created_at": "2026-09-11T23:14:59Z"
}
```

### 8.3. Consultar Observaciones de Red Sanitizadas

**Petición:**
```http
GET /api/descubrimientos/e8b2c451-93c1-4b1c-99d8-9df24f114c0a/observaciones/
```

Retorna el historial completo de solicitudes y tramas interceptadas, garantizando que tokens, contraseñas y valores de cookies se encuentren redactados (`[REDACTADO]`).

### 8.4. Diagnóstico de Salud de Ollama (IA Local)

**Petición:**
```http
GET /api/sistema/ollama/
```

**Respuesta (200 OK cuando está disponible):**
```json
{
  "disponible": true,
  "modelo_configurado": "llama3.2",
  "modelo_presente": true,
  "modelos_disponibles": [
    "llama3.2:latest",
    "deepseek-r1:latest"
  ],
  "error": null
}
```

---

## 9. Capa de Inteligencia Artificial Semántica Local (Ollama)

### 9.1. Filosofía de Integración
- **Heurística + Determinismo Primero**: Playwright y la inspección de red capturan los hechos técnicos comprobables (presencia del marcador, HTTP status, selectores).
- **IA Solo para Ambigüedad**: Si un elemento o petición cuenta con coincidencia directa del marcador y confianza alta (`score >= 0.95`), la IA **no** se invoca.
- **Tolerancia a Fallos Absoluta**: Si Ollama no está instalado, está apagado o falla, el sistema continúa funcionando 100% de forma determinista sin bloquear el análisis.
- **Seguridad y Privacidad Estricta**: Nunca se envían cookies, tokens, encabezados sensibles ni credenciales a los prompts del LLM.

### 9.2. Ponderación y Combinación de Confianza
Cuando Ollama interviene para desambiguar el canal, la confianza final se calcula ponderando:
$$\text{Confianza Final} = (0.65 \times \text{Score Heurístico}) + (0.35 \times \text{Score IA})$$

### 9.3. Configuración en `.env`
```env
OLLAMA_ENABLED=True
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2
OLLAMA_TIMEOUT_SECONDS=15.0
OLLAMA_TEMPERATURE=0.1
OLLAMA_MAX_RETRIES=2
OLLAMA_MIN_HEURISTIC_CONFIDENCE=0.80
```

---

## 10. Políticas de Seguridad Implementadas


1. **Protección contra SSRF**: El validador rechaza esquemas no autorizados (`file://`, `ftp://`, `javascript:`, etc.) y verifica el dominio contra `ALLOWED_TARGET_HOSTS`.
2. **Sanitización de Datos en Tránsito y Reposo**: Ningún valor de `Authorization`, `Cookie`, `X-API-Key` o contraseñas en payloads JSON/formularios es guardado en texto plano.
3. **Contención de Navegación**: Se ejecutan contextos independientes de Chromium sin persistencia de estado cruzado.
4. **Protección de Capacidad**: Limitación estricta de cantidad máxima de requests capturados y truncado de payloads voluminosos.

---

## 10. Limitaciones Actuales y Roadmap

### Limitaciones del MVP
- Inicio de sesión automatizado para interfaces protegidas por autenticación compleja (preparado para fase posterior).
- Análisis heurístico enfocado en Chromium (no ejecuta WebKit/Firefox simultáneamente).
- SPAs que requieran resolución de CAPTCHA.

### Roadmap Futuro
- [ ] Incorporación de módulo de almacenamiento y reutilización temporal de `storage_state` para sesiones autenticadas.
- [ ] Soporte para análisis de entrada de audio (WebRTC / MediaStream).
- [ ] Integración de módulos de auditoría de seguridad para **Prompt Injection**, **RAG Injection** y **Persistent Prompt Injection**.
- [ ] Soporte opcional de tareas distribuidas mediante Celery y Redis.
