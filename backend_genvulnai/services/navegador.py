"""
Servicio para la administración del ciclo de vida del navegador automatizado Playwright.
Utiliza la API síncrona con contextos independientes para cada análisis.
"""
import logging
from typing import Optional
from django.conf import settings
from playwright.sync_api import sync_playwright, Playwright, Browser, BrowserContext, Page
from backend_genvulnai.exceptions import NavegacionError

logger = logging.getLogger('backend_genvulnai')


class NavegadorService:
    """Administra la instancia de Chromium con aislamiento y políticas de contención."""

    def __init__(
        self,
        headless: Optional[bool] = None,
        timeout_segundos: Optional[int] = None,
        usuario: Optional[str] = None,
        contrasena: Optional[str] = None
    ):
        self.headless = headless if headless is not None else getattr(settings, 'PLAYWRIGHT_HEADLESS', True)
        self.timeout_segundos = timeout_segundos if timeout_segundos is not None else getattr(settings, 'DISCOVERY_TIMEOUT_SECONDS', 30)
        self.timeout_ms = self.timeout_segundos * 1000
        self.usuario = usuario
        self.contrasena = contrasena

        self._playwright: Optional[Playwright] = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._page: Optional[Page] = None

    def __enter__(self) -> "NavegadorService":
        self.iniciar()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cerrar()

    def iniciar(self) -> None:
        """Inicia Playwright y crea una instancia limpia de Chromium."""
        try:
            self._playwright = sync_playwright().start()
            self._browser = self._playwright.chromium.launch(
                headless=self.headless,
                args=[
                    '--disable-web-security',
                    '--disable-features=IsolateOrigins,site-per-process',
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                ]
            )
            # Contexto aislado por análisis, bloqueando service workers e inyectando headers de túneles
            context_kwargs = {
                'ignore_https_errors': True,
                'viewport': {'width': 1280, 'height': 800},
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 AI-Discovery-Agent/1.0',
                'service_workers': 'block',
                'extra_http_headers': {
                    'X-Tunnel-Skip-Anti-Abuse': 'true',
                    'bypass-tunnel-reminder': 'true',
                    'ngrok-skip-browser-warning': 'true',
                }
            }
            if self.usuario and self.contrasena:
                context_kwargs['http_credentials'] = {
                    'username': self.usuario,
                    'password': self.contrasena
                }

            self._context = self._browser.new_context(**context_kwargs)
            self._context.set_default_timeout(self.timeout_ms)
            self._page = self._context.new_page()
        except Exception as err:
            self.cerrar()
            logger.error(f"Error al inicializar Playwright: {err}")
            raise NavegacionError(f"No fue posible inicializar el navegador Chromium: {err}")

    def navegar(self, url: str) -> Page:
        """Navega a la URL objetivo con control de tiempos, bypass de túnel y espera de red."""
        if not self._page:
            raise NavegacionError("El navegador no ha sido inicializado.")

        try:
            logger.info(f"Navegando hacia el objetivo: {url}")
            # Usar 'domcontentloaded' para mayor tolerancia en SPAs
            self._page.goto(url, wait_until='domcontentloaded', timeout=self.timeout_ms)
            
            # Superar posibles pantallas de advertencia de túneles (DevTunnels / Ngrok / Localtunnel)
            self._superar_intersticiales_tunel(self._page)

            # Esperar a que la SPA estabilice peticiones dinámicas
            try:
                self._page.wait_for_load_state('networkidle', timeout=5000)
            except Exception:
                pass
            self._page.wait_for_timeout(2000)
            return self._page
        except Exception as err:
            logger.error(f"Fallo en la navegación a {url}: {err}")
            raise NavegacionError(f"Fallo al cargar la página objetivo {url}: {err}")

    def _superar_intersticiales_tunel(self, page: Page) -> None:
        """Detecta y supera avisos o pantallas de consentimiento comunes en túneles."""
        try:
            botones_continuar = [
                'button:has-text("Continue")',
                'button:has-text("Continuar")',
                'input[type="submit"][value*="Continue" i]',
                'input[type="submit"][value*="Continuar" i]',
                '#proceed-button',
                'a:has-text("Click here to proceed")',
            ]
            for sel in botones_continuar:
                loc = page.locator(sel)
                if loc.count() > 0 and loc.first.is_visible():
                    logger.info(f"Detectada pantalla intersticial de túnel. Pulsando botón de continuación: {sel}")
                    loc.first.click(timeout=3000)
                    page.wait_for_timeout(2000)
                    break
        except Exception as err:
            logger.debug(f"Aviso al verificar intersticial de túnel: {err}")

    def obtener_pagina(self) -> Page:
        """Retorna la página activa."""
        if not self._page:
            raise NavegacionError("No hay una página activa disponible.")
        return self._page

    def obtener_cookies(self) -> dict:
        """Retorna las cookies del contexto actual de navegación como un diccionario {nombre: valor}."""
        if not self._context:
            return {}
        try:
            raw_cookies = self._context.cookies()
            return {c['name']: c['value'] for c in raw_cookies}
        except Exception as err:
            logger.warning(f"Error al extraer cookies del contexto Playwright: {err}")
            return {}

    def obtener_contexto(self) -> Optional[BrowserContext]:
        """Retorna el contexto del navegador Playwright."""
        return self._context


    def cerrar(self) -> None:
        """Libera de manera segura todos los recursos del navegador."""
        try:
            if self._page:
                self._page.close()
            if self._context:
                self._context.close()
            if self._browser:
                self._browser.close()
            if self._playwright:
                self._playwright.stop()
        except Exception as err:
            logger.warning(f"Aviso durante el cierre de Playwright: {err}")
        finally:
            self._page = None
            self._context = None
            self._browser = None
            self._playwright = None
