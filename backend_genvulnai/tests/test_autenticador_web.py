"""
Pruebas unitarias para el servicio de autenticación web automatizada y soporte de credenciales.
"""
import pytest
from unittest.mock import MagicMock, patch
from backend_genvulnai.serializers import IniciarEscaneoSerializer
from backend_genvulnai.services.autenticador_web import AutenticadorWebService
from backend_genvulnai.services.navegador import NavegadorService


def test_serializer_con_usuario_y_contrasena():
    """Valida que IniciarEscaneoSerializer acepte usuario y contrasena."""
    data = {
        "url": "http://localhost:3000",
        "usuario": "admin",
        "contrasena": "Secreto123!"
    }
    serializer = IniciarEscaneoSerializer(data=data)
    assert serializer.is_valid(), serializer.errors
    assert serializer.validated_data["usuario"] == "admin"
    assert serializer.validated_data["contrasena"] == "Secreto123!"


def test_serializer_con_aliases_username_y_password():
    """Valida que IniciarEscaneoSerializer normalice los aliases username y password."""
    data = {
        "url": "http://localhost:3000",
        "username": "tester",
        "password": "Password456!"
    }
    serializer = IniciarEscaneoSerializer(data=data)
    assert serializer.is_valid(), serializer.errors
    assert serializer.validated_data["usuario"] == "tester"
    assert serializer.validated_data["contrasena"] == "Password456!"


def test_es_pantalla_login_por_url():
    """Valida que identifique pantallas de login a partir de la URL."""
    mock_page = MagicMock()
    mock_page.url = "https://936lzz7p-4200.brs.devtunnels.ms/login"
    mock_page.locator.return_value.count.return_value = 0

    assert AutenticadorWebService.es_pantalla_login(mock_page) is True


def test_es_pantalla_login_por_password_input():
    """Valida que identifique formulario de login si hay un campo password visible."""
    mock_page = MagicMock()
    mock_page.url = "https://936lzz7p-4200.brs.devtunnels.ms/home"
    
    mock_locator = MagicMock()
    mock_locator.count.return_value = 1
    mock_locator.nth.return_value.is_visible.return_value = True
    mock_page.locator.return_value = mock_locator

    assert AutenticadorWebService.es_pantalla_login(mock_page) is True


def test_intentar_autenticacion_sin_credenciales():
    """Valida que retorne False si faltan credenciales."""
    mock_page = MagicMock()
    mock_page.url = "https://936lzz7p-4200.brs.devtunnels.ms/login"
    assert AutenticadorWebService.intentar_autenticacion(mock_page, usuario="", contrasena="") is False
    assert AutenticadorWebService.intentar_autenticacion(mock_page, usuario="admin", contrasena="") is False

    res = AutenticadorWebService.evaluar_e_intentar_autenticacion(mock_page, usuario="", contrasena="")
    assert res.pantalla_login_detectada is True
    assert res.credenciales_suministradas is False
    assert res.exitoso is False
    assert "requiere inicio de sesión" in res.mensaje


def test_evaluar_autenticacion_fallida():
    """Valida diagnóstico cuando se envían credenciales pero el formulario sigue visible."""
    mock_page = MagicMock()
    mock_page.url = "https://936lzz7p-4200.brs.devtunnels.ms/login"

    mock_pwd = MagicMock()
    mock_pwd.is_visible.return_value = True

    mock_user = MagicMock()
    mock_user.is_visible.return_value = True
    mock_user.get_attribute.return_value = "text"

    mock_btn = MagicMock()
    mock_btn.is_visible.return_value = True

    def locator_side_effect(selector):
        loc = MagicMock()
        if 'password' in selector:
            loc.count.return_value = 1
            loc.nth.return_value = mock_pwd
        elif 'user' in selector or 'email' in selector or 'text' in selector:
            loc.count.return_value = 1
            loc.nth.return_value = mock_user
        elif 'submit' in selector or 'iniciar' in selector or 'login' in selector:
            loc.count.return_value = 1
            loc.nth.return_value = mock_btn
        else:
            loc.count.return_value = 0
        return loc

    mock_page.locator.side_effect = locator_side_effect

    # No cambia la URL (sigue en /login)
    res = AutenticadorWebService.evaluar_e_intentar_autenticacion(
        mock_page,
        usuario="admin@gmail.com",
        contrasena="wrongpass"
    )

    assert res.pantalla_login_detectada is True
    assert res.credenciales_suministradas is True
    assert res.exitoso is False
    assert "no funcionó" in res.mensaje



def test_intentar_autenticacion_exito():
    """Valida flujo exitoso de autenticación llenando inputs y haciendo submit."""
    mock_page = MagicMock()
    mock_page.url = "https://example.com/login"

    # Mock para input de password
    mock_pwd = MagicMock()
    mock_pwd.is_visible.return_value = True
    
    # Mock para input de usuario
    mock_user = MagicMock()
    mock_user.is_visible.return_value = True
    mock_user.get_attribute.return_value = "text"

    # Mock para botón de submit
    mock_btn = MagicMock()
    mock_btn.is_visible.return_value = True

    def locator_side_effect(selector):
        loc = MagicMock()
        if 'password' in selector:
            loc.count.return_value = 1
            loc.nth.return_value = mock_pwd
        elif 'user' in selector or 'email' in selector or 'text' in selector:
            loc.count.return_value = 1
            loc.nth.return_value = mock_user
        elif 'submit' in selector or 'iniciar' in selector or 'login' in selector:
            loc.count.return_value = 1
            loc.nth.return_value = mock_btn
        else:
            loc.count.return_value = 0
        return loc

    mock_page.locator.side_effect = locator_side_effect

    # Simular cambio de URL tras login
    def wait_side_effect(*args, **kwargs):
        mock_page.url = "https://example.com/dashboard"
        mock_pwd.is_visible.return_value = False

    mock_page.wait_for_timeout.side_effect = wait_side_effect

    resultado = AutenticadorWebService.intentar_autenticacion(
        mock_page,
        usuario="admin",
        contrasena="ClaveSegura123"
    )

    assert resultado is True
    mock_user.fill.assert_called_with("admin")
    mock_pwd.fill.assert_called_with("ClaveSegura123")


@patch('backend_genvulnai.services.navegador.sync_playwright')
def test_navegador_service_headers_y_credenciales(mock_sync_playwright):
    """Valida que NavegadorService configure cabeceras de túnel y credenciales HTTP básicas."""
    mock_playwright_inst = MagicMock()
    mock_browser = MagicMock()
    mock_context = MagicMock()
    mock_page = MagicMock()

    mock_sync_playwright.return_value.start.return_value = mock_playwright_inst
    mock_playwright_inst.chromium.launch.return_value = mock_browser
    mock_browser.new_context.return_value = mock_context
    mock_context.new_page.return_value = mock_page

    with NavegadorService(usuario="admin", contrasena="pass123") as nav:
        call_kwargs = mock_browser.new_context.call_args[1]
        extra_headers = call_kwargs.get('extra_http_headers', {})
        assert extra_headers.get('X-Tunnel-Skip-Anti-Abuse') == 'true'
        assert extra_headers.get('bypass-tunnel-reminder') == 'true'
        assert extra_headers.get('ngrok-skip-browser-warning') == 'true'
        
        http_creds = call_kwargs.get('http_credentials')
        assert http_creds == {'username': 'admin', 'password': 'pass123'}


def test_descubridor_interfaz_descarta_formulario_login():
    """Valida que inputs con nombre username o en pantallas de login se descarten como interfaz de IA."""
    from backend_genvulnai.services.descubridor_interfaz import DescubridorInterfazService
    from backend_genvulnai.domain.enums import TipoInterfaz

    mock_page = MagicMock()
    mock_input = MagicMock()
    mock_input.is_visible.return_value = True
    mock_input.evaluate.return_value = 'input'
    mock_input.get_attribute.side_effect = lambda attr: {
        'type': 'text',
        'name': 'username',
        'placeholder': 'Correo electrónico o usuario',
        'id': 'user_field',
        'autocomplete': 'username'
    }.get(attr, '')
    mock_input.is_editable.return_value = True

    mock_locator = MagicMock()
    mock_locator.all.return_value = [mock_input]
    mock_page.locator.return_value = mock_locator

    resultado = DescubridorInterfazService.descubrir_interfaz(mock_page)
    assert resultado.tipo == TipoInterfaz.DESCONOCIDO
    assert resultado.selector_entrada is None

