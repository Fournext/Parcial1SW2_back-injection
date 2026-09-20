"""
Servicio para detección y ejecución de autenticación web automatizada.
Permite autenticar al agente de descubrimiento ante formularios de login (Angular, React, Vue, HTML estándar)
previo a la fase de exploración del DOM y detección de interfaces de IA.
"""
import logging
from dataclasses import dataclass
from typing import Optional
from playwright.sync_api import Page

logger = logging.getLogger('backend_genvulnai')


@dataclass
class ResultadoIntentoAutenticacion:
    """Detalla el estado y resultado del intento de autenticación web."""
    pantalla_login_detectada: bool = False
    credenciales_suministradas: bool = False
    intento_realizado: bool = False
    exitoso: bool = False
    mensaje: str = "No se detectó pantalla de inicio de sesión."
    url_previa: str = ""
    url_posterior: str = ""


class AutenticadorWebService:
    """Detecta pantallas de autenticación e interactúa con formularios de login."""

    SELECTORES_USUARIO = [
        'input[autocomplete="username"]',
        'input[autocomplete="email"]',
        'input[name*="user" i]',
        'input[name*="email" i]',
        'input[name*="login" i]',
        'input[name*="account" i]',
        'input[name*="identif" i]',
        'input[id*="user" i]',
        'input[id*="email" i]',
        'input[id*="login" i]',
        'input[placeholder*="usuario" i]',
        'input[placeholder*="email" i]',
        'input[placeholder*="correo" i]',
        'input[type="email"]',
        'input[type="text"]',
    ]

    SELECTORES_BOTON_LOGIN = [
        'button[type="submit"]',
        'input[type="submit"]',
        'button:has-text("iniciar")',
        'button:has-text("ingresar")',
        'button:has-text("login")',
        'button:has-text("sign in")',
        'button:has-text("entrar")',
        'button:has-text("acceder")',
        'button:has-text("log in")',
    ]

    @classmethod
    def es_pantalla_login(cls, page: Page) -> bool:
        """Determina si la página actual corresponde a una pantalla o formulario de autenticación."""
        try:
            # 1. Verificar por URL típica de login
            url_actual = (page.url or '').lower()
            palabras_clave_url = ['/login', '/signin', '/auth', '/ingresar', '/acceder']
            if any(kw in url_actual for kw in palabras_clave_url):
                return True

            # 2. Verificar por input de tipo contraseña visible
            try:
                password_inputs = page.locator('input[type="password"]')
                count = password_inputs.count()
                if isinstance(count, int) and count > 0:
                    for idx in range(count):
                        if password_inputs.nth(idx).is_visible():
                            return True
            except Exception:
                pass

            return False
        except Exception as err:
            logger.debug(f"Error comprobando pantalla de login: {err}")
            return False

    @classmethod
    def evaluar_e_intentar_autenticacion(
        cls,
        page: Page,
        usuario: Optional[str] = None,
        contrasena: Optional[str] = None
    ) -> ResultadoIntentoAutenticacion:
        """
        Evalúa si la vista actual es una pantalla de login y, en su caso, ejecuta
        el inicio de sesión con las credenciales suministradas, reportando el diagnóstico.
        """
        url_actual = page.url or ""
        es_login = cls.es_pantalla_login(page)
        if not es_login:
            return ResultadoIntentoAutenticacion(
                pantalla_login_detectada=False,
                credenciales_suministradas=bool(usuario and contrasena),
                intento_realizado=False,
                exitoso=False,
                mensaje="No se detectó pantalla de inicio de sesión.",
                url_previa=url_actual,
                url_posterior=url_actual
            )

        # La vista es una pantalla de login
        if not usuario or not contrasena:
            mensaje = (
                f"La aplicación objetivo requiere inicio de sesión en '{url_actual}', pero no se suministraron "
                "credenciales (usuario y contraseña). Envíe las credenciales para acceder a las interfaces internas."
            )
            logger.warning(mensaje)
            return ResultadoIntentoAutenticacion(
                pantalla_login_detectada=True,
                credenciales_suministradas=False,
                intento_realizado=False,
                exitoso=False,
                mensaje=mensaje,
                url_previa=url_actual,
                url_posterior=url_actual
            )

        url_previa = url_actual
        logger.info(f"Detectada pantalla de login en {url_previa}. Iniciando autenticación automática para usuario '{usuario}'...")

        try:
            # 1. Localizar campo de usuario
            input_usuario = None
            for sel in cls.SELECTORES_USUARIO:
                loc = page.locator(sel)
                count = loc.count()
                for i in range(count):
                    candidate = loc.nth(i)
                    if candidate.is_visible():
                        tipo = candidate.get_attribute('type') or ''
                        if tipo.lower() != 'password':
                            input_usuario = candidate
                            break
                if input_usuario:
                    break

            if not input_usuario:
                msg_err = f"No se pudo localizar el campo de usuario o email en el formulario de login en '{url_previa}'."
                logger.warning(msg_err)
                return ResultadoIntentoAutenticacion(
                    pantalla_login_detectada=True,
                    credenciales_suministradas=True,
                    intento_realizado=False,
                    exitoso=False,
                    mensaje=msg_err,
                    url_previa=url_previa,
                    url_posterior=url_previa
                )

            # 2. Localizar campo de contraseña
            input_password = None
            pwd_loc = page.locator('input[type="password"]')
            for i in range(pwd_loc.count()):
                if pwd_loc.nth(i).is_visible():
                    input_password = pwd_loc.nth(i)
                    break

            if not input_password:
                msg_err = f"No se pudo localizar el campo de contraseña visible en '{url_previa}'."
                logger.warning(msg_err)
                return ResultadoIntentoAutenticacion(
                    pantalla_login_detectada=True,
                    credenciales_suministradas=True,
                    intento_realizado=False,
                    exitoso=False,
                    mensaje=msg_err,
                    url_previa=url_previa,
                    url_posterior=url_previa
                )

            # 3. Llenar campo de usuario
            input_usuario.click()
            input_usuario.fill(usuario)
            page.wait_for_timeout(300)

            # 4. Llenar campo de contraseña
            input_password.click()
            input_password.fill(contrasena)
            page.wait_for_timeout(400)

            # 5. Encontrar y activar botón de envío
            boton_enviado = False
            for sel_btn in cls.SELECTORES_BOTON_LOGIN:
                btn = page.locator(sel_btn)
                for b_idx in range(btn.count()):
                    cand_btn = btn.nth(b_idx)
                    if cand_btn.is_visible():
                        try:
                            cand_btn.click(timeout=3000)
                            boton_enviado = True
                            break
                        except Exception:
                            pass
                if boton_enviado:
                    break

            if not boton_enviado:
                logger.info("Botón de submit no localizado; enviando formulario con Enter en el campo de contraseña.")
                input_password.press("Enter")

            # 6. Esperar transición de red o cambio de URL
            try:
                page.wait_for_load_state('networkidle', timeout=6000)
            except Exception:
                pass
            page.wait_for_timeout(2500)

            url_posterior = page.url or url_previa
            logger.info(f"URL tras intento de login: {url_posterior}")

            # 7. Validar éxito de la autenticación
            formulario_aun_visible = False
            try:
                if input_password.is_visible():
                    formulario_aun_visible = True
            except Exception:
                formulario_aun_visible = False

            if url_posterior != url_previa or not formulario_aun_visible:
                msg_ok = f"Inicio de sesión exitoso con el usuario '{usuario}'. Se accedió a '{url_posterior}'."
                logger.info(msg_ok)
                return ResultadoIntentoAutenticacion(
                    pantalla_login_detectada=True,
                    credenciales_suministradas=True,
                    intento_realizado=True,
                    exitoso=True,
                    mensaje=msg_ok,
                    url_previa=url_previa,
                    url_posterior=url_posterior
                )
            else:
                msg_fail = (
                    f"El inicio de sesión no funcionó para el usuario '{usuario}'. El formulario de autenticación "
                    f"continúa activo en '{url_posterior}' tras el intento de ingreso (verifique credenciales o servicio de auth)."
                )
                logger.warning(msg_fail)
                return ResultadoIntentoAutenticacion(
                    pantalla_login_detectada=True,
                    credenciales_suministradas=True,
                    intento_realizado=True,
                    exitoso=False,
                    mensaje=msg_fail,
                    url_previa=url_previa,
                    url_posterior=url_posterior
                )

        except Exception as err:
            msg_exc = f"Error durante el proceso de autenticación automática: {err}"
            logger.error(msg_exc)
            return ResultadoIntentoAutenticacion(
                pantalla_login_detectada=True,
                credenciales_suministradas=True,
                intento_realizado=True,
                exitoso=False,
                mensaje=msg_exc,
                url_previa=url_previa,
                url_posterior=page.url or url_previa
            )

    @classmethod
    def intentar_autenticacion(
        cls,
        page: Page,
        usuario: Optional[str] = None,
        contrasena: Optional[str] = None
    ) -> bool:
        """Compatibilidad: ejecuta la evaluación y retorna booleano de éxito."""
        resultado = cls.evaluar_e_intentar_autenticacion(page, usuario, contrasena)
        return resultado.exitoso

