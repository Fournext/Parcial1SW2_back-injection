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

    def __init__(self, headless: Optional[bool] = None, timeout_segundos: Optional[int] = None):
        self.headless = headless if headless is not None else getattr(settings, 'PLAYWRIGHT_HEADLESS', True)
        self.timeout_segundos = timeout_segundos if timeout_segundos is not None else getattr(settings, 'DISCOVERY_TIMEOUT_SECONDS', 30)
        self.timeout_ms = self.timeout_segundos * 1000

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
            # Contexto aislado por análisis, bloqueando service workers si es necesario
            self._context = self._browser.new_context(
                ignore_https_errors=True,
                viewport={'width': 1280, 'height': 800},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 AI-Discovery-Agent/1.0',
                service_workers='block'
            )
            self._context.set_default_timeout(self.timeout_ms)
            self._page = self._context.new_page()
        except Exception as err:
            self.cerrar()
            logger.error(f"Error al inicializar Playwright: {err}")
            raise NavegacionError(f"No fue posible inicializar el navegador Chromium: {err}")

    def navegar(self, url: str) -> Page:
        """Navega a la URL objetivo con control de tiempos y espera de red."""
        if not self._page:
            raise NavegacionError("El navegador no ha sido inicializado.")

        try:
            logger.info(f"Navegando hacia el objetivo: {url}")
            # Usar 'domcontentloaded' para mayor tolerancia en SPAs
            self._page.goto(url, wait_until='domcontentloaded', timeout=self.timeout_ms)
            # Breve pausa para dar tiempo al renderizado de interfaces JS dinámicas
            self._page.wait_for_timeout(2000)
            return self._page
        except Exception as err:
            logger.error(f"Fallo en la navegación a {url}: {err}")
            raise NavegacionError(f"Fallo al cargar la página objetivo {url}: {err}")

    def obtener_pagina(self) -> Page:
        """Retorna la página activa."""
        if not self._page:
            raise NavegacionError("No hay una página activa disponible.")
        return self._page

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
