"""
Pruebas unitarias para el ExploradorDOMService (Crawler de Fuzzing del DOM).
Valida:
1. Detección directa si la vista inicial ya contiene inputs.
2. Búsqueda y priorización heurística de elementos clickeables (botones de chat, widgets, links).
3. Transición de estados y re-análisis del DOM tras clicks.
4. Protección contra bucles infinitos y enlaces a dominios externos.
5. Respeto al límite configurado de pasos y profundidad.
"""
from unittest.mock import MagicMock, patch
import pytest

from backend_genvulnai.domain.schemas import (
    ElementoInteractivo,
    ElementoCandidato,
    ResultadoInterfaz,
)
from backend_genvulnai.domain.enums import TipoInterfaz, MetodoEnvio
from backend_genvulnai.services.explorador_dom import ExploradorDOMService


def test_es_navegacion_interna_permite_mismo_dominio_y_relativas():
    """Valida que URLs relativas y del mismo host sean consideradas internas."""
    base = "http://localhost:3000/app"
    
    assert ExploradorDOMService._es_navegacion_interna(base, "http://localhost:3000/chat") is True
    assert ExploradorDOMService._es_navegacion_interna(base, "http://localhost:3000/api/v1") is True
    assert ExploradorDOMService._es_navegacion_interna(base, "/dashboard") is True
    assert ExploradorDOMService._es_navegacion_interna(base, "http://127.0.0.1:3000/chat") is False
    assert ExploradorDOMService._es_navegacion_interna(base, "https://google.com") is False
    assert ExploradorDOMService._es_navegacion_interna(base, "javascript:void(0)") is False


def test_priorizacion_heuristica_relevancia():
    """Elementos con palabras de chat/IA o botones flotantes deben tener mayor puntuación."""
    elem_chat = ElementoInteractivo(
        selector="#btn-chat",
        tag_name="button",
        texto_visible="Abrir Asistente IA",
        aria_label="chat widget",
        clases="floating-button widget-chat"
    )
    score_chat = ExploradorDOMService._calcular_relevancia(elem_chat)

    elem_generico = ElementoInteractivo(
        selector="a[href='/terminos']",
        tag_name="a",
        texto_visible="Términos y condiciones",
        href="/terminos",
        clases="nav-link"
    )
    score_generico = ExploradorDOMService._calcular_relevancia(elem_generico)

    assert score_chat > score_generico
    assert score_chat >= 5.0  # Recibe bonificaciones por chat, botón, floating widget


def test_explorar_retorna_inmediatamente_si_vista_inicial_tiene_interfaz():
    """Si la página ya tiene inputs de IA, no gasta pasos explorando."""
    mock_page = MagicMock()
    mock_page.url = "http://localhost:3000/"

    candidato = ElementoCandidato(
        selector="#prompt-input",
        tag_name="textarea",
        tipo_elemento="textarea",
        puntuacion=8.0,
        placeholder="Escribe tu mensaje...",
        es_editable=True
    )

    with patch('backend_genvulnai.services.descubridor_interfaz.DescubridorInterfazService.obtener_candidatos_entrada', return_value=[candidato]):
        res, estado = ExploradorDOMService.explorar_hasta_encontrar_interfaz(mock_page, "http://localhost:3000/")

        assert res is not None
        assert res.selector_entrada == "#prompt-input"
        assert estado.interfaz_encontrada is True
        assert estado.pasos_realizados == 0


def test_explorar_sin_elementos_interactivos():
    """Si no hay inputs ni elementos clickeables, finaliza sin error."""
    mock_page = MagicMock()
    mock_page.url = "http://localhost:3000/"

    # Primera comprobación: no hay inputs
    with patch('backend_genvulnai.services.descubridor_interfaz.DescubridorInterfazService.obtener_candidatos_entrada', return_value=[]):
        with patch.object(ExploradorDOMService, '_descubrir_elementos_interactivos', return_value=[]):
            res, estado = ExploradorDOMService.explorar_hasta_encontrar_interfaz(mock_page, "http://localhost:3000/")

            assert res is None
            assert estado.interfaz_encontrada is False
            assert estado.pasos_realizados == 0


def test_explorar_descubre_interfaz_tras_hacer_click():
    """Simula que un botón de chat abre un modal con un campo textarea de IA."""
    mock_page = MagicMock()
    mock_page.url = "http://localhost:3000/"

    # Simular elementos interactivos encontrados en la vista inicial
    boton_chat = ElementoInteractivo(
        selector="#open-chat-btn",
        tag_name="button",
        texto_visible="Chat con Asistente",
        puntuacion_relevancia=6.0
    )

    candidato_encontrado = ElementoCandidato(
        selector="#modal-textarea",
        tag_name="textarea",
        tipo_elemento="textarea",
        puntuacion=7.5,
        placeholder="Haz una pregunta...",
        es_editable=True
    )

    # 1era llamada a obtener_candidatos_entrada: vacío (vista inicial)
    # 2da llamada a obtener_candidatos_entrada: encuentra candidato (tras click)
    mock_inputs = [[], [candidato_encontrado]]

    with patch('backend_genvulnai.services.descubridor_interfaz.DescubridorInterfazService.obtener_candidatos_entrada', side_effect=mock_inputs):
        with patch.object(ExploradorDOMService, '_descubrir_elementos_interactivos', return_value=[boton_chat]):
            with patch.object(ExploradorDOMService, '_ejecutar_click_seguro', return_value=True):
                # Simular que el hash de DOM cambia tras el click (abrió modal)
                with patch.object(ExploradorDOMService, '_obtener_hash_dom', side_effect=["hash_inicial", "hash_inicial", "hash_modal", "hash_modal"]):
                    res, estado = ExploradorDOMService.explorar_hasta_encontrar_interfaz(
                        mock_page, 
                        "http://localhost:3000/", 
                        max_pasos=5
                    )

                    assert res is not None
                    assert res.selector_entrada == "#modal-textarea"
                    assert estado.interfaz_encontrada is True
                    assert estado.pasos_realizados == 1
                    assert len(estado.ruta_hasta_interfaz) == 1
                    assert estado.ruta_hasta_interfaz[0]["selector"] == "#open-chat-btn"


def test_explorar_detiene_al_alcanzar_max_pasos():
    """Verifica que el ciclo se detenga una vez alcanzado max_pasos."""
    mock_page = MagicMock()
    mock_page.url = "http://localhost:3000/"

    # Múltiples botones que no descubren interfaz
    botones = [
        ElementoInteractivo(selector=f"#btn-{i}", tag_name="button", texto_visible=f"Boton {i}", puntuacion_relevancia=1.0)
        for i in range(10)
    ]

    with patch('backend_genvulnai.services.descubridor_interfaz.DescubridorInterfazService.obtener_candidatos_entrada', return_value=[]):
        with patch.object(ExploradorDOMService, '_descubrir_elementos_interactivos', return_value=botones):
            with patch.object(ExploradorDOMService, '_ejecutar_click_seguro', return_value=True):
                with patch.object(ExploradorDOMService, '_obtener_hash_dom', return_value="hash_constante"):
                    res, estado = ExploradorDOMService.explorar_hasta_encontrar_interfaz(
                        mock_page, 
                        "http://localhost:3000/", 
                        max_pasos=3
                    )

                    assert res is None
                    assert estado.interfaz_encontrada is False
                    assert estado.pasos_realizados == 3


from unittest.mock import MagicMock, PropertyMock, patch


def test_explorar_evita_loops_y_navegaciones_externas():
    """Verifica que si un enlace redirige a un dominio externo, retroceda y no lo agregue."""
    mock_page = MagicMock()
    
    link_externo = ElementoInteractivo(
        selector="#link-externo",
        tag_name="a",
        texto_visible="Redes Sociales",
        href="https://twitter.com",
        puntuacion_relevancia=0.5
    )

    # El navegador empieza en localhost:3000 y tras el click cambia a twitter.com
    type(mock_page).url = PropertyMock(side_effect=[
        "http://localhost:3000/",           # inicial
        "http://localhost:3000/",           # url_antes
        "https://twitter.com/mi_cuenta",   # url_despues
        "https://twitter.com/mi_cuenta",   # chequeos posteriores
        "https://twitter.com/mi_cuenta"
    ])

    with patch('backend_genvulnai.services.descubridor_interfaz.DescubridorInterfazService.obtener_candidatos_entrada', return_value=[]):
        with patch.object(ExploradorDOMService, '_descubrir_elementos_interactivos', return_value=[link_externo]):
            with patch.object(ExploradorDOMService, '_ejecutar_click_seguro', return_value=True):
                with patch.object(ExploradorDOMService, '_intentar_volver_atras') as mock_volver:
                    res, estado = ExploradorDOMService.explorar_hasta_encontrar_interfaz(
                        mock_page, 
                        "http://localhost:3000/", 
                        max_pasos=1
                    )

                    assert res is None
                    assert mock_volver.called


def test_input_generico_sin_keywords_es_descartado():
    """Valida que un input genérico cuyo marcador no aparece en red es descartado."""
    mock_page = MagicMock()
    mock_page.url = "http://localhost:3000/"
    mock_locator = MagicMock()
    mock_locator.first.is_visible.return_value = True
    mock_page.locator.return_value = mock_locator

    candidato_generico = ElementoCandidato(
        selector='input[type="text"]:nth-of-type(1)',
        tag_name="input",
        tipo_elemento="input",
        puntuacion=1.0,
        es_editable=True
    )

    marcador = "DISCOVERY_TEST_fake"
    mock_capturador = MagicMock()
    # Sin peticiones con el marcador
    mock_capturador.obtener_observaciones_http.return_value = []
    mock_capturador.obtener_observaciones_ws.return_value = []

    with patch('backend_genvulnai.services.descubridor_interfaz.DescubridorInterfazService.obtener_candidatos_entrada', return_value=[candidato_generico]):
        with patch.object(ExploradorDOMService, '_descubrir_elementos_interactivos', return_value=[]):
            res, estado = ExploradorDOMService.explorar_hasta_encontrar_interfaz(
                mock_page,
                "http://localhost:3000/",
                marcador=marcador,
                capturador=mock_capturador
            )

            assert res is None
            assert estado.interfaz_encontrada is False
            # Debe haber intentado vaciar el input descartado
            assert mock_locator.first.fill.called


def test_input_confirmado_cuando_marcador_en_red():
    """Valida que un input se confirma exitosamente cuando el marcador se detecta en red."""
    mock_page = MagicMock()
    mock_page.url = "http://localhost:3000/"
    mock_locator = MagicMock()
    mock_locator.first.is_visible.return_value = True
    mock_page.locator.return_value = mock_locator

    candidato = ElementoCandidato(
        selector="#chat-input",
        tag_name="textarea",
        tipo_elemento="textarea",
        puntuacion=7.0,
        es_editable=True
    )

    marcador = "DISCOVERY_TEST_valid123"
    obs_red = MagicMock()
    obs_red.body_original = f'{{"mensaje": "{marcador}"}}'
    obs_red.url = "http://localhost:3000/api/prompt"

    mock_capturador = MagicMock()
    # Primera llamada (antes de inyectar): vacía
    # Segunda llamada (tras inyectar): contiene la petición con el marcador
    mock_capturador.obtener_observaciones_http.side_effect = [[], [obs_red]]
    mock_capturador.obtener_observaciones_ws.return_value = []

    with patch('backend_genvulnai.services.descubridor_interfaz.DescubridorInterfazService.obtener_candidatos_entrada', return_value=[candidato]):
        res, estado = ExploradorDOMService.explorar_hasta_encontrar_interfaz(
            mock_page,
            "http://localhost:3000/",
            marcador=marcador,
            capturador=mock_capturador
        )

        assert res is not None
        assert res.selector_entrada == "#chat-input"
        assert estado.interfaz_encontrada is True


def test_explora_tras_falso_positivo():
    """
    Simula la situación real:
    1. En la vista inicial hay un input genérico (ID de diagrama) -> el sondeo no detecta el marcador en red -> descartado.
    2. El explorador interactúa con el botón de chat -> abre modal con textarea.
    3. El textarea es sondeado -> el marcador aparece en red -> ¡interfaz confirmada!
    """
    mock_page = MagicMock()
    mock_page.url = "http://localhost:3000/"
    mock_locator = MagicMock()
    mock_locator.first.is_visible.return_value = True
    mock_page.locator.return_value = mock_locator

    marcador = "DISCOVERY_TEST_cycle"

    input_falso = ElementoCandidato(
        selector='input[type="text"]:nth-of-type(1)',
        tag_name="input",
        tipo_elemento="input",
        puntuacion=1.0,
        es_editable=True
    )

    boton_chat = ElementoInteractivo(
        selector="#btn-chat-ia",
        tag_name="button",
        texto_visible="Chat IA",
        puntuacion_relevancia=6.0
    )

    input_real = ElementoCandidato(
        selector="#chat-prompt-textarea",
        tag_name="textarea",
        tipo_elemento="textarea",
        puntuacion=8.0,
        es_editable=True
    )

    obs_exitosa = MagicMock()
    obs_exitosa.body_original = f'{{"prompt": "{marcador}"}}'
    obs_exitosa.url = "http://localhost:3000/api/ai"

    # Capturador:
    # 1. obs antes de input falso: []
    # 2. obs tras input falso: []  (no hubo tráfico con marcador)
    # 3. obs antes de input real: []
    # 4. obs tras input real: [obs_exitosa]
    mock_capturador = MagicMock()
    mock_capturador.obtener_observaciones_http.side_effect = [
        [],                 # antes del input falso
        [],                 # tras el input falso (FALLA)
        [],                 # antes del input real
        [obs_exitosa],      # tras el input real (ÉXITO)
    ]
    mock_capturador.obtener_observaciones_ws.return_value = []

    mock_inputs_por_llamada = [
        [input_falso],      # Vista inicial
        [input_real],       # Tras hacer clic en botón chat
    ]

    with patch('backend_genvulnai.services.descubridor_interfaz.DescubridorInterfazService.obtener_candidatos_entrada', side_effect=mock_inputs_por_llamada):
        with patch.object(ExploradorDOMService, '_descubrir_elementos_interactivos', return_value=[boton_chat]):
            with patch.object(ExploradorDOMService, '_ejecutar_click_seguro', return_value=True):
                with patch.object(ExploradorDOMService, '_obtener_hash_dom', side_effect=["hash1", "hash1", "hash2", "hash2"]):
                    res, estado = ExploradorDOMService.explorar_hasta_encontrar_interfaz(
                        mock_page,
                        "http://localhost:3000/",
                        marcador=marcador,
                        capturador=mock_capturador,
                        max_pasos=5
                    )

                    assert res is not None
                    assert res.selector_entrada == "#chat-prompt-textarea"
                    assert estado.interfaz_encontrada is True
                    assert estado.pasos_realizados == 1
                    assert len(estado.ruta_hasta_interfaz) == 1
                    assert estado.ruta_hasta_interfaz[0]["selector"] == "#btn-chat-ia"


def test_exploracion_profundidad_hasta_10_niveles():
    """Valida que el explorador admita y recorra niveles de profundidad hasta 10."""
    mock_page = MagicMock()
    # Simular cambios de URL sucesivos hasta 6 niveles
    urls_simuladas = [
        "http://localhost:3000/lvl1",
        "http://localhost:3000/lvl2",
        "http://localhost:3000/lvl3",
        "http://localhost:3000/lvl4",
        "http://localhost:3000/lvl5",
        "http://localhost:3000/lvl6",
    ]
    mock_page.url = "http://localhost:3000/"

    # Un botón en cada nivel
    boton_nav = ElementoInteractivo(
        selector="#nav-next",
        tag_name="button",
        texto_visible="Siguiente",
        puntuacion_relevancia=2.0
    )

    def efecto_click(*args, **kwargs):
        if urls_simuladas:
            mock_page.url = urls_simuladas.pop(0)
        return True

    with patch('backend_genvulnai.services.descubridor_interfaz.DescubridorInterfazService.obtener_candidatos_entrada', return_value=[]):
        with patch.object(ExploradorDOMService, '_descubrir_elementos_interactivos', return_value=[boton_nav]):
            with patch.object(ExploradorDOMService, '_ejecutar_click_seguro', side_effect=efecto_click):
                with patch.object(ExploradorDOMService, '_obtener_hash_dom', side_effect=[f"hash_{i}" for i in range(50)]):
                    res, estado = ExploradorDOMService.explorar_hasta_encontrar_interfaz(
                        mock_page,
                        "http://localhost:3000/",
                        max_pasos=6,
                        max_profundidad=10
                    )

                    assert estado.pasos_realizados == 6
                    assert estado.profundidad_actual >= 5
                    assert len(estado.urls_visitadas) >= 5


def test_backtracking_dfs_vuelve_a_nivel_anterior():
    """
    Valida que si una vista profunda se queda sin elementos interactivos,
    el crawler desapile y vuelva a la URL del nivel anterior en lugar de abortar abruptamente.
    """
    mock_page = MagicMock()
    mock_page.url = "http://localhost:3000/app"

    boton_nivel1 = ElementoInteractivo(
        selector="#ir-a-subvista",
        tag_name="button",
        texto_visible="Subvista",
        puntuacion_relevancia=2.0
    )

    llamadas_volver = []

    def mock_volver(page, url_destino):
        llamadas_volver.append(url_destino)
        mock_page.url = url_destino
        return True

    # Simular cambio de url en el primer click
    def click_cambia_url(*args, **kwargs):
        mock_page.url = "http://localhost:3000/app/subvista"
        return True

    # Paso 1: Hay botón en nivel 1 -> Navega a /app/subvista
    # Paso 2: En /app/subvista no hay elementos disponibles -> Hace backtracking a /app
    # Paso 3: En /app tras volver no hay más elementos -> Finaliza
    with patch('backend_genvulnai.services.descubridor_interfaz.DescubridorInterfazService.obtener_candidatos_entrada', return_value=[]):
        with patch.object(ExploradorDOMService, '_descubrir_elementos_interactivos', side_effect=[[boton_nivel1], [], []]):
            with patch.object(ExploradorDOMService, '_ejecutar_click_seguro', side_effect=click_cambia_url):
                with patch.object(ExploradorDOMService, '_intentar_volver_atras', side_effect=mock_volver):
                    with patch.object(ExploradorDOMService, '_obtener_hash_dom', side_effect=["h1", "h1", "h2", "h2", "h3", "h4"]):
                        res, estado = ExploradorDOMService.explorar_hasta_encontrar_interfaz(
                            mock_page,
                            "http://localhost:3000/app",
                            max_pasos=4,
                            max_profundidad=10
                        )

                        # Verificamos que se ejecutó backtracking a la URL previa en la pila
                        assert "http://localhost:3000/app" in llamadas_volver


def test_penalizacion_colapsar_y_acciones_destructivas():
    """Valida que elementos con 'colapsar', 'collapse' o 'salir' sean severamente penalizados."""
    elem_colapsar = ElementoInteractivo(
        selector="button#btn-collapse",
        tag_name="button",
        texto_visible="COLAPSAR",
        clases="btn-toggle sidebar-action"
    )
    score_colapsar = ExploradorDOMService._calcular_relevancia(elem_colapsar)
    assert score_colapsar <= -5.0

    elem_salir = ElementoInteractivo(
        selector="button#btn-logout",
        tag_name="button",
        texto_visible="Cerrar sesión",
        clases="btn-danger"
    )
    score_salir = ExploradorDOMService._calcular_relevancia(elem_salir)
    assert score_salir <= -8.0


def test_priorizacion_expandir_y_links_navegacion():
    """Valida que botones de menú hamburguesa y links de navegación tengan mayor score que botones genéricos."""
    elem_hamburguesa = ElementoInteractivo(
        selector="button.mat-icon-button",
        tag_name="button",
        texto_visible="",
        aria_label="Abrir menú de navegación",
        clases="mat-icon-button menu-toggle"
    )
    score_hamburguesa = ExploradorDOMService._calcular_relevancia(elem_hamburguesa)

    elem_link_nav = ElementoInteractivo(
        selector="a[routerlink='/chat']",
        tag_name="a",
        texto_visible="Chat IA Asistente",
        href="/chat",
        clases="mat-list-item nav-link"
    )
    score_link = ExploradorDOMService._calcular_relevancia(elem_link_nav)

    elem_generico = ElementoInteractivo(
        selector="button#btn-ok",
        tag_name="button",
        texto_visible="Aceptar",
        clases="btn-default"
    )
    score_generico = ExploradorDOMService._calcular_relevancia(elem_generico)

    assert score_link > score_hamburguesa > score_generico
    assert score_generico < 2.0


def test_asegurar_menu_expandido_despliega_hamburguesa():
    """Valida que _asegurar_menu_expandido localice y cliquee el botón de menú hamburguesa."""
    mock_page = MagicMock()
    # Menos de 3 links visibles
    mock_page.locator.return_value.count.return_value = 0

    mock_btn = MagicMock()
    mock_btn.is_visible.return_value = True
    mock_btn.inner_text.return_value = "Menú"
    mock_page.locator.return_value.all.return_value = [mock_btn]

    resultado = ExploradorDOMService._asegurar_menu_expandido(mock_page)
    assert resultado is True
    assert mock_btn.click.called


def test_priorizacion_pestana_ia_sobre_menu_generico():
    """Valida que una pestaña con IA explícita tenga mayor prioridad que enlaces neutros."""
    elem_tab_ia = ElementoInteractivo(
        selector='button:has-text("Reportes Inteligentes (IA)")',
        tag_name="button",
        texto_visible="Reportes Inteligentes (IA)",
        clases="pb-3 text-sm font-bold border-b-2 text-indigo-600"
    )
    score_tab_ia = ExploradorDOMService._calcular_relevancia(elem_tab_ia)

    elem_link_tareas = ElementoInteractivo(
        selector="#tour-tareas",
        tag_name="a",
        texto_visible="Bandeja de Tareas",
        href="/mis-tareas",
        title="Bandeja de Tareas",
        clases="flex items-center gap-3 px-3 py-3"
    )
    score_link_tareas = ExploradorDOMService._calcular_relevancia(elem_link_tareas)

    assert score_tab_ia > score_link_tareas
    assert score_tab_ia >= 10.0


def test_penalizacion_conmutador_tema():
    """Valida que botones de tema claro/oscuro sean penalizados para no desperdiciar pasos."""
    elem_theme = ElementoInteractivo(
        selector="#tour-theme",
        tag_name="button",
        texto_visible="",
        aria_label="Toggle theme",
        clases="p-2 rounded-xl"
    )
    score_theme = ExploradorDOMService._calcular_relevancia(elem_theme)
    assert score_theme <= -5.0


def test_enlaces_tour_tienen_bonificacion_de_navegacion():
    """Valida que enlaces principales de navegación del tour reciban bonificación."""
    elem_diagramas = ElementoInteractivo(
        selector="#tour-diagramador",
        tag_name="a",
        texto_visible="Diagramador",
        href="/diagramas",
        title="Diagramador UML",
        clases="flex items-center gap-3"
    )
    score_diagramas = ExploradorDOMService._calcular_relevancia(elem_diagramas)
    assert score_diagramas >= 7.0


def test_asegurar_selects_activos_selecciona_opcion():
    """Valida que un <select> con placeholder active la primera opción real."""
    mock_page = MagicMock()
    mock_sel = MagicMock()
    mock_sel.input_value.return_value = ""
    mock_sel.inner_text.return_value = "-- Seleccionar Proyecto --"
    mock_sel.locator.return_value.all.return_value = [MagicMock(), MagicMock()]
    mock_page.locator.return_value.all.return_value = [mock_sel]

    cambio = ExploradorDOMService._asegurar_selects_activos(mock_page)
    assert cambio is True
    mock_sel.select_option.assert_called_with(index=1)


def test_prioridad_asistente_ia_y_editar_modelo_diagramador():
    """Valida que el Asistente IA y el botón Editar Modelo tengan máxima prioridad sobre navegación genérica."""
    elem_asistente = ElementoInteractivo(
        selector='button:has-text("Asistente IA")',
        tag_name="button",
        texto_visible="Asistente IA",
        clases="tab-btn active text-sm font-semibold"
    )
    score_asistente = ExploradorDOMService._calcular_relevancia(elem_asistente)

    elem_editar_modelo = ElementoInteractivo(
        selector='button:has-text("Editar Modelo")',
        tag_name="button",
        texto_visible="Editar Modelo",
        clases="px-4 py-2 bg-indigo-600 text-white rounded-lg"
    )
    score_editar = ExploradorDOMService._calcular_relevancia(elem_editar_modelo)

    elem_tareas = ElementoInteractivo(
        selector="#tour-tareas",
        tag_name="a",
        texto_visible="Bandeja de Tareas",
        href="/mis-tareas"
    )
    score_tareas = ExploradorDOMService._calcular_relevancia(elem_tareas)

    assert score_asistente >= 15.0
    assert score_editar >= 12.0
    assert score_asistente > score_editar > score_tareas


def test_prioridad_boton_consultar_ia():
    """Valida que el botón Consultar IA tenga alta prioridad de interacción."""
    elem_consultar = ElementoInteractivo(
        selector='button:has-text("Consultar IA")',
        tag_name="button",
        texto_visible="Consultar IA",
        clases="btn-primary"
    )
    score_consultar = ExploradorDOMService._calcular_relevancia(elem_consultar)
    assert score_consultar >= 8.0





