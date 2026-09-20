"""
Servicio para la exploración activa e interactiva del DOM (Crawler de Fuzzing del DOM).
Rastrea botones, enlaces, widgets y pestañas para revelar interfaces de IA ocultas tras
modales, sidebars, rutas internas o componentes desplegables.
"""
import hashlib
import logging
import urllib.parse
from typing import List, Optional, Tuple, Set, Dict, Any

from playwright.sync_api import Page

from backend_genvulnai.domain.constants import (
    EventosLog,
    MAX_PASOS_EXPLORACION,
    MAX_PROFUNDIDAD_NAVEGACION,
    TIEMPO_ESPERA_TRAS_CLICK_MS,
    MAX_ELEMENTOS_POR_PAGINA,
    SELECTORES_EXPLORABLES,
    PALABRAS_CLAVE_EXPLORACION,
    PALABRAS_CLAVE_COLAPSAR,
    PALABRAS_CLAVE_EXPANDIR,
    PUNTUACION_MINIMA_INPUT_CONFIABLE,
    PALABRAS_CLAVE_ENDPOINT_AUTH,
)
from backend_genvulnai.domain.enums import MetodoEnvio
from backend_genvulnai.domain.schemas import (
    ElementoInteractivo,
    ElementoCandidato,
    EstadoExploracion,
    ResultadoInterfaz,
)
from backend_genvulnai.services.descubridor_interfaz import DescubridorInterfazService

logger = logging.getLogger('backend_genvulnai')


class ExploradorDOMService:
    """Explora sistemáticamente el DOM buscando interfaces de IA ocultas o desplegables."""

    @classmethod
    def _probar_input_y_verificar_red(
        cls,
        page: Page,
        candidato: ElementoCandidato,
        marcador: Optional[str] = None,
        capturador: Optional[Any] = None,
    ) -> bool:
        """
        Inyecta el marcador en un candidato, envía, espera y verifica si alguna
        petición de red (HTTP o WebSocket) transmitió el marcador. Retorna True si se confirmó.
        """
        if not capturador or not marcador:
            return True

        # 1. Contar observaciones antes de inyectar
        obs_antes = len(capturador.obtener_observaciones_http())
        ws_list_antes = capturador.obtener_observaciones_ws()
        ws_counts_antes = [len(ws.frames_enviados) for ws in ws_list_antes]

        # 2. Intentar inyectar el marcador
        try:
            boton = DescubridorInterfazService._encontrar_boton_envio(page, candidato.selector)
            input_loc = page.locator(candidato.selector).first
            if not input_loc.is_visible():
                return False

            input_loc.click(timeout=2000)
            input_loc.fill(marcador)
            # Notificar eventos de cambio para reactividad de Angular
            try:
                input_loc.dispatch_event('input')
                input_loc.dispatch_event('change')
            except Exception:
                pass
            page.wait_for_timeout(500)

            metodo = MetodoEnvio.ENTER
            click_exitoso = False

            if boton:
                btn_loc = page.locator(boton.selector).first
                if btn_loc.is_visible():
                    try:
                        btn_loc.click(timeout=2000)
                        metodo = MetodoEnvio.BOTON
                        click_exitoso = True
                    except Exception as err_btn:
                        logger.debug(f"Click en botón {boton.selector} falló: {err_btn}")

            # Si no hubo botón o el clic falló, buscar botones en el contenedor padre del input (ej. botones con SVG o submit)
            if not click_exitoso:
                try:
                    contenedor_padre = page.locator(f'{candidato.selector}/ancestor::*[self::form or self::div or self::section][1]')
                    btn_cercanos = contenedor_padre.locator('button:visible').all()
                    for btn_c in btn_cercanos:
                        texto_c = (btn_c.inner_text() or '').strip().lower()
                        tiene_svg = btn_c.locator('svg').count() > 0
                        if any(v in texto_c for v in ('consultar', 'enviar', 'send', 'generar')) or tiene_svg:
                            btn_c.click(timeout=2000)
                            metodo = MetodoEnvio.BOTON
                            click_exitoso = True
                            break
                except Exception:
                    pass

            # Si sigue sin haber botón, intentar buscar botones de acción visibles por texto prioritario
            if not click_exitoso:
                for btn_action_text in ['consultar ia', 'consultar', 'generar', 'enviar', 'send', 'submit', 'generate', 'analizar', 'ejecutar']:
                    try:
                        btn_action = page.locator(f'button:has-text("{btn_action_text}")').first
                        if btn_action.is_visible():
                            btn_action.click(timeout=2000)
                            metodo = MetodoEnvio.BOTON
                            click_exitoso = True
                            break
                    except Exception:
                        pass

            # Si sigue sin enviarse y es textarea: probar Control+Enter y Enter
            if not click_exitoso:
                if candidato.tag_name == 'textarea':
                    try:
                        input_loc.press("Control+Enter")
                    except Exception:
                        pass
                    input_loc.press("Enter")
                else:
                    input_loc.press("Enter")

            logger.info(
                f"[{EventosLog.MARKER_SENT}] Marcador {marcador} inyectado mediante {metodo} en {candidato.selector}"
            )
        except Exception as err:
            logger.warning(f"No se pudo inyectar en {candidato.selector}: {err}")
            return False

        # 3. Esperar respuesta de red
        page.wait_for_timeout(3000)

        # 4. Verificar si ALGUNA petición HTTP nueva contiene el marcador
        obs_actuales = capturador.obtener_observaciones_http()
        obs_nuevas = obs_actuales[obs_antes:]

        for obs in obs_nuevas:
            # Ignorar peticiones a endpoints de autenticación o que contengan credenciales
            url_path = obs.url.split('?')[0].lower()
            if any(pat in url_path for pat in PALABRAS_CLAVE_ENDPOINT_AUTH):
                continue
            body_lower = (obs.body_original or '').lower()
            if any(p in body_lower for p in ('"password"', '"contrasena"', '"contraseña"', '"passwd"')):
                continue

            if marcador in (obs.body_original or '') or marcador in (obs.url or ''):
                return True

        # 5. Verificar si algún frame WebSocket nuevo contiene el marcador
        ws_actuales = capturador.obtener_observaciones_ws()
        for idx, ws in enumerate(ws_actuales):
            frames_previos = ws_counts_antes[idx] if idx < len(ws_counts_antes) else 0
            for frame in ws.frames_enviados[frames_previos:]:
                if marcador in frame:
                    return True

        return False

    @classmethod
    def explorar_hasta_encontrar_interfaz(
        cls,
        page: Page,
        url_base: str,
        marcador: Optional[str] = None,
        capturador: Optional[Any] = None,
        max_pasos: int = MAX_PASOS_EXPLORACION,
        max_profundidad: int = MAX_PROFUNDIDAD_NAVEGACION,
    ) -> Tuple[Optional[ResultadoInterfaz], EstadoExploracion]:
        """
        Ciclo principal de exploración interactiva con validación de red:
        1. Comprueba si la vista actual contiene inputs y los sondea con el marcador.
        2. Si no confirman en red, extrae y prioriza elementos interactivos explorables.
        3. Realiza clics secuenciales controlados, evaluando si el estado cambia.
        4. En cada nuevo estado, re-analiza y sondea nuevos campos de entrada.
        5. Evita loops mediante hashing de DOM y control de URLs e inputs visitados.
        """
        estado = EstadoExploracion()
        url_actual = page.url or url_base
        estado.urls_visitadas.append(url_actual)

        hash_inicial = cls._obtener_hash_dom(page)
        estado.hashes_dom_visitados.append(hash_inicial)

        inputs_ya_probados: Set[str] = set()

        # 0. Asegurar menú expandido y selects activos si la vista tiene controles condicionales
        cls._asegurar_menu_expandido(page)
        cls._asegurar_selects_activos(page)

        # 1. Comprobación inicial directa con prueba y verificación de red
        candidatos_iniciales = DescubridorInterfazService.obtener_candidatos_entrada(page)
        if candidatos_iniciales:
            candidatos_iniciales.sort(key=lambda c: c.puntuacion, reverse=True)
            for cand in candidatos_iniciales:
                inputs_ya_probados.add(cand.selector)
                logger.info(
                    f"[{EventosLog.PROBE_INPUT_STARTED}] Evaluando input inicial {cand.selector} (score={cand.puntuacion:.1f})"
                )
                if cls._probar_input_y_verificar_red(page, cand, marcador, capturador):
                    logger.info(
                        f"[{EventosLog.PROBE_INPUT_CONFIRMED}] ¡Marcador confirmado en red! Input inicial: {cand.selector}"
                    )
                    res_int = DescubridorInterfazService.construir_resultado_desde_candidato(
                        page, cand, len(candidatos_iniciales)
                    )
                    estado.interfaz_encontrada = True
                    return res_int, estado
                else:
                    logger.info(
                        f"[{EventosLog.PROBE_INPUT_FAILED}] Marcador NO detectado en red para {cand.selector}. Descartando."
                    )
                    try:
                        page.locator(cand.selector).first.fill("", timeout=500)
                    except Exception:
                        pass

            # Si el sondeo inicial provocó navegación (ej. unirse/crear sala en SPA)
            if page.url and page.url != url_actual:
                url_actual = page.url
                if url_actual not in estado.urls_visitadas:
                    estado.urls_visitadas.append(url_actual)
                cls._asegurar_menu_expandido(page)
                candidatos_nav = DescubridorInterfazService.obtener_candidatos_entrada(page)
                candidatos_nav_filtrados = [
                    c for c in candidatos_nav if c.selector not in inputs_ya_probados
                ]
                if candidatos_nav_filtrados:
                    candidatos_nav_filtrados.sort(key=lambda c: c.puntuacion, reverse=True)
                    for cand in candidatos_nav_filtrados:
                        inputs_ya_probados.add(cand.selector)
                        logger.info(
                            f"[{EventosLog.PROBE_INPUT_STARTED}] Evaluando input tras navegación inicial {cand.selector} (score={cand.puntuacion:.1f})"
                        )
                        if cls._probar_input_y_verificar_red(page, cand, marcador, capturador):
                            logger.info(
                                f"[{EventosLog.PROBE_INPUT_CONFIRMED}] ¡Marcador confirmado en red! Input: {cand.selector}"
                            )
                            res_int = DescubridorInterfazService.construir_resultado_desde_candidato(
                                page, cand, len(candidatos_nav)
                            )
                            estado.interfaz_encontrada = True
                            return res_int, estado
                        else:
                            logger.info(
                                f"[{EventosLog.PROBE_INPUT_FAILED}] Marcador NO detectado en red para {cand.selector}. Descartando."
                            )
                            try:
                                page.locator(cand.selector).first.fill("", timeout=500)
                            except Exception:
                                pass

        estados_visitados: Set[Tuple[str, str]] = {(url_actual, hash_inicial)}
        elementos_ya_probados: Set[Tuple[str, str]] = set()
        historial_navegacion: List[str] = [url_actual]

        logger.info(
            f"[{EventosLog.EXPLORER_STARTED}] Iniciando exploración activa en {url_base} "
            f"(máx pasos: {max_pasos}, máx prof: {max_profundidad})"
        )

        while estado.pasos_realizados < max_pasos:
            url_antes = page.url
            hash_antes = cls._obtener_hash_dom(page)

            # Asegurar que los menús o sidebars estén visibles antes de extraer elementos
            cls._asegurar_menu_expandido(page)

            # Descubrir elementos en la vista actual
            elementos = cls._descubrir_elementos_interactivos(page, estado.urls_visitadas)

            # Filtrar elementos ya probados en esta vista y omitir elementos con penalización severa (colapso/destructivos)
            elementos_disponibles = [
                elem for elem in elementos
                if (url_antes, elem.selector) not in elementos_ya_probados and elem.puntuacion_relevancia > -5.0
            ]

            if not elementos_disponibles:
                logger.info(f"No hay más elementos interactivos por explorar en {url_antes}.")
                # Si tenemos historial de navegación previo, retroceder al nivel anterior (Backtracking DFS)
                if len(historial_navegacion) > 1:
                    historial_navegacion.pop()
                    url_destino_volver = historial_navegacion[-1]
                    logger.info(f"Backtracking DFS al nivel anterior: {url_destino_volver}")
                    cls._intentar_volver_atras(page, url_destino_volver)
                    cls._asegurar_menu_expandido(page)
                    estado.profundidad_actual = max(0, len(historial_navegacion) - 1)
                    continue
                # Si estamos en la raíz y ya no hay elementos, terminar exploración
                break

            # Tomar el elemento con mayor relevancia
            elem_a_probar = elementos_disponibles[0]
            elementos_ya_probados.add((url_antes, elem_a_probar.selector))
            estado.elementos_clickeados.append(elem_a_probar.selector)
            estado.pasos_realizados += 1

            logger.info(
                f"[{EventosLog.EXPLORER_CLICK}] Paso #{estado.pasos_realizados}: "
                f"Clic en '{elem_a_probar.texto_visible or elem_a_probar.tag_name}' "
                f"[{elem_a_probar.selector}] (relevancia: {elem_a_probar.puntuacion_relevancia:.1f}, prof: {estado.profundidad_actual}/{max_profundidad})"
            )

            # Realizar interacción con control de excepciones
            click_exitoso = cls._ejecutar_click_seguro(page, elem_a_probar.selector)
            if not click_exitoso:
                continue

            # Pausa para renderizado y transiciones
            page.wait_for_timeout(TIEMPO_ESPERA_TRAS_CLICK_MS)

            url_despues = page.url
            hash_despues = cls._obtener_hash_dom(page)

            # Verificar si salimos del dominio permitido
            if not cls._es_navegacion_interna(url_base, url_despues):
                logger.warning(
                    f"Clic causó navegación externa a {url_despues}. Retornando a {url_base}"
                )
                cls._intentar_volver_atras(page, url_antes)
                cls._asegurar_menu_expandido(page)
                continue

            # Detectar si hubo cambio de estado significativo
            es_misma = cls._es_misma_vista(hash_antes, hash_despues, url_antes, url_despues)
            estado_par = (url_despues, hash_despues)

            if estado_par in estados_visitados:
                logger.debug(f"[{EventosLog.EXPLORER_LOOP_DETECTED}] Estado ya conocido {estado_par[0]}.")
                # Si navegó a una URL ya visitada (ej. volver al Dashboard desde Mis Tareas),
                # no forzar retroceso destructivo para permitir continuar navegando al resto del menú
                if not es_misma and url_despues != url_antes:
                    logger.debug(f"Navegación a ruta conocida {url_despues}. Manteniendo posición para explorar elementos pendientes.")
                continue

            estados_visitados.add(estado_par)

            tipo_cambio = "ninguno"
            if url_despues != url_antes:
                tipo_cambio = "navegacion"
                historial_navegacion.append(url_despues)
                estado.profundidad_actual = max(0, len(historial_navegacion) - 1)
                if url_despues not in estado.urls_visitadas:
                    estado.urls_visitadas.append(url_despues)
                logger.info(
                    f"[{EventosLog.EXPLORER_NAVIGATION}] Nueva URL detectada: {url_despues} "
                    f"(profundidad actual: {estado.profundidad_actual}/{max_profundidad})"
                )
            elif not es_misma:
                tipo_cambio = "modal_o_sidebar"
                logger.info(f"[{EventosLog.EXPLORER_STATE_CHANGE}] Cambio en DOM detectado (modal/desplegable).")

            # Registrar en la ruta de exploración
            paso_info = {
                "paso": estado.pasos_realizados,
                "selector": elem_a_probar.selector,
                "texto": elem_a_probar.texto_visible,
                "url_origen": url_antes,
                "url_destino": url_despues,
                "tipo_cambio": tipo_cambio,
            }
            estado.ruta_hasta_interfaz.append(paso_info)

            # Asegurar que si la acción reveló un dropdown condicional (*ngIf como proyectos/modelos), se active
            cambio_sel = cls._asegurar_selects_activos(page)
            if cambio_sel:
                page.wait_for_timeout(1000)

            # Buscar y probar cualquier input no probado en la vista resultante del clic
            candidatos_nuevos = DescubridorInterfazService.obtener_candidatos_entrada(page)
            candidatos_filtrados = [
                c for c in candidatos_nuevos if c.selector not in inputs_ya_probados
            ]

            # Si el elemento clickeado era de IA y aún no hay inputs visibles, reintentar tras breve pausa por renderizado reactivo
            if not candidatos_filtrados and any(k in (elem_a_probar.texto_visible or '').lower() for k in ('ia', 'reporte', 'asistente', 'modelo', 'consultar')):
                page.wait_for_timeout(1200)
                cls._asegurar_selects_activos(page)
                candidatos_nuevos = DescubridorInterfazService.obtener_candidatos_entrada(page)
                candidatos_filtrados = [
                    c for c in candidatos_nuevos if c.selector not in inputs_ya_probados
                ]

            if candidatos_filtrados:
                candidatos_filtrados.sort(key=lambda c: c.puntuacion, reverse=True)
                for cand in candidatos_filtrados:
                    inputs_ya_probados.add(cand.selector)
                    logger.info(
                        f"[{EventosLog.PROBE_INPUT_STARTED}] Evaluando nuevo input tras paso #{estado.pasos_realizados}: "
                        f"{cand.selector} (score={cand.puntuacion:.1f})"
                    )
                    if cls._probar_input_y_verificar_red(page, cand, marcador, capturador):
                        res_interfaz = DescubridorInterfazService.construir_resultado_desde_candidato(
                            page, cand, len(candidatos_nuevos)
                        )
                        estado.interfaz_encontrada = True
                        logger.info(
                            f"[{EventosLog.EXPLORER_INTERFACE_FOUND}] ¡Interfaz de IA confirmada en "
                            f"paso #{estado.pasos_realizados}! Input: {res_interfaz.selector_entrada}"
                        )
                        return res_interfaz, estado
                    else:
                        logger.info(
                            f"[{EventosLog.PROBE_INPUT_FAILED}] Marcador NO detectado en red para {cand.selector}. Descartando."
                        )
                        try:
                            page.locator(cand.selector).first.fill("", timeout=500)
                        except Exception:
                            pass

            # Si excedimos profundidad, retroceder al nivel anterior
            if estado.profundidad_actual >= max_profundidad:
                logger.info(f"Profundidad máxima alcanzada ({max_profundidad}). Retrocediendo...")
                if len(historial_navegacion) > 1:
                    historial_navegacion.pop()
                    url_volver = historial_navegacion[-1]
                    cls._intentar_volver_atras(page, url_volver)
                    cls._asegurar_menu_expandido(page)
                    estado.profundidad_actual = max(0, len(historial_navegacion) - 1)
                else:
                    cls._intentar_volver_atras(page, url_base)
                    cls._asegurar_menu_expandido(page)
                    estado.profundidad_actual = 0

        if estado.pasos_realizados >= max_pasos:
            logger.info(f"[{EventosLog.EXPLORER_MAX_STEPS}] Límite de pasos alcanzado ({max_pasos}).")

        logger.info(
            f"[{EventosLog.EXPLORER_FINISHED}] Fin de exploración sin encontrar interfaz confirmada. "
            f"Pasos: {estado.pasos_realizados}, URLs: {len(estado.urls_visitadas)}"
        )
        return None, estado

    @classmethod
    def _asegurar_menu_expandido(cls, page: Page) -> bool:
        """
        Si la vista actual tiene un menú colapsado o hamburguesa y pocos enlaces de navegación visibles,
        intenta abrirlo para revelar los enlaces internos de la SPA.
        """
        try:
            # Contar enlaces de navegación visibles actualmente
            links_visibles = page.locator(
                'nav a:visible, aside a:visible, mat-nav-list a:visible, .sidebar a:visible, [role="navigation"] a:visible, mat-list-item:visible'
            ).count()
            if links_visibles >= 3:
                # Ya hay suficientes enlaces de navegación visibles en el DOM
                return False

            # Buscar botón hamburguesa o toggle de menú
            selectores_menu = [
                'button[aria-label*="menu" i]',
                'button[aria-label*="menú" i]',
                'button.mat-icon-button',
                'mat-toolbar button',
                '.mat-toolbar button',
                '.hamburger',
                '.hamburger-menu',
                '[class*="hamburger" i]',
                '[class*="toggle" i][class*="nav" i]',
                'button[aria-label*="navegación" i]',
                'button[aria-label*="navigation" i]',
            ]
            for sel in selectores_menu:
                botones = page.locator(sel).all()
                for btn in botones[:5]:
                    if not btn.is_visible():
                        continue
                    texto_btn = (btn.inner_text() or '').lower()
                    # Evitar botones que explícitamente colapsan
                    if any(c in texto_btn for c in PALABRAS_CLAVE_COLAPSAR):
                        continue
                    logger.info(f"Desplegando menú/sidebar potencialmente colapsado mediante {sel}")
                    btn.click(timeout=1500)
                    page.wait_for_timeout(1000)
                    return True
        except Exception as err:
            logger.debug(f"Aviso al asegurar menú expandido: {err}")
        return False

    @classmethod
    def _asegurar_selects_activos(cls, page: Page) -> bool:
        """
        Si la vista actual contiene elementos <select> (como selectores de proyectos,
        modelos o filtros) que están en su opción por defecto vacía, selecciona la primera
        opción válida para desplegar los inputs condicionales (*ngIf).
        """
        hubo_cambio = False
        try:
            selects = page.locator('select:visible').all()
            for sel in selects:
                try:
                    valor = sel.input_value()
                    opciones = sel.locator('option').all()
                    if len(opciones) > 1 and (not valor or valor == "" or valor == "0" or "seleccionar" in (sel.inner_text() or '').lower()):
                        sel.select_option(index=1)
                        try:
                            sel.dispatch_event('change')
                            sel.dispatch_event('input')
                        except Exception:
                            pass
                        page.wait_for_timeout(1000)
                        hubo_cambio = True
                        logger.info("Activado selector <select> (índice 1) para revelar campos condicionales.")
                except Exception as err_sel:
                    logger.debug(f"Aviso al activar select: {err_sel}")
        except Exception as err:
            logger.debug(f"Aviso buscando selects activos: {err}")
        return hubo_cambio

    @classmethod
    def _descubrir_elementos_interactivos(
        cls, 
        page: Page, 
        urls_visitadas: Optional[List[str]] = None
    ) -> List[ElementoInteractivo]:
        """Extrae y califica heurísticamente los elementos clickeables en la vista activa."""
        candidatos: List[ElementoInteractivo] = []
        selectores_vistos: Set[str] = set()

        for selector_base in SELECTORES_EXPLORABLES:
            try:
                elementos = page.locator(selector_base).all()
                for idx, elem in enumerate(elementos[:MAX_ELEMENTOS_POR_PAGINA]):
                    if not elem.is_visible():
                        continue

                    tag_name = elem.evaluate('el => el.tagName.toLowerCase()')
                    texto = (elem.inner_text() or '').strip()[:100]
                    href = elem.get_attribute('href')
                    aria_label = elem.get_attribute('aria-label') or ''
                    title = elem.get_attribute('title') or ''
                    clases = elem.get_attribute('class') or ''
                    id_attr = elem.get_attribute('id') or ''
                    router_link = elem.get_attribute('routerlink') or elem.get_attribute('ng-reflect-router-link')
                    data_testid = elem.get_attribute('data-testid')

                    # Si no tiene href pero tiene routerLink de Angular, usarlo como href para análisis heurístico
                    if not href and router_link:
                        href = router_link

                    # Selector preciso y reproducible
                    if id_attr:
                        selector_especifico = f"#{id_attr}"
                    elif data_testid:
                        selector_especifico = f"[data-testid=\"{data_testid}\"]"
                    elif elem.get_attribute('routerlink'):
                        rl = elem.get_attribute('routerlink').replace('"', '\\"')
                        selector_especifico = f"[routerlink=\"{rl}\"]"
                    elif elem.get_attribute('ng-reflect-router-link'):
                        nrl = elem.get_attribute('ng-reflect-router-link').replace('"', '\\"')
                        selector_especifico = f"[ng-reflect-router-link=\"{nrl}\"]"
                    elif href and tag_name == 'a':
                        href_limpio = href.replace('"', '\\"')
                        selector_especifico = f"a[href=\"{href_limpio}\"]"
                    elif tag_name == 'button' and texto and len(texto) <= 40 and '\n' not in texto:
                        txt_escaped = texto.replace('"', '\\"')
                        selector_especifico = f'button:has-text("{txt_escaped}")'
                    else:
                        selector_especifico = f"{selector_base}:nth-of-type({idx + 1})" if ':nth' not in selector_base else selector_base

                    if selector_especifico in selectores_vistos:
                        continue
                    selectores_vistos.add(selector_especifico)

                    candidato = ElementoInteractivo(
                        selector=selector_especifico,
                        tag_name=tag_name,
                        texto_visible=texto,
                        href=href,
                        aria_label=aria_label,
                        title=title,
                        clases=clases,
                    )
                    candidato.puntuacion_relevancia = cls._calcular_relevancia(candidato, urls_visitadas)
                    candidatos.append(candidato)

            except Exception as err:
                logger.debug(f"Error evaluando selector explorable {selector_base}: {err}")

        # Ordenar por mayor relevancia heurística
        candidatos.sort(key=lambda item: item.puntuacion_relevancia, reverse=True)
        return candidatos

    @classmethod
    def _calcular_relevancia(
        cls, 
        elemento: ElementoInteractivo, 
        urls_visitadas: Optional[List[str]] = None
    ) -> float:
        """Puntúa un elemento según su probabilidad de desplegar o llevar a una interfaz de IA."""
        texto_completo = f"{elemento.texto_visible} {elemento.aria_label or ''} {elemento.title or ''} {elemento.clases or ''} {elemento.href or ''} {elemento.selector}".lower()

        # 1. Penalización severa e inmediata para acciones destructivas o de salida (evitar salir de la app)
        for palabra_peligrosa in (
            'salir', 'exit', 'volver', 'back', 'logout', 'cerrar sesión',
            'cerrar sesion', 'eliminar', 'delete', 'borrar', 'cancelar', 'cancel'
        ):
            if palabra_peligrosa in texto_completo:
                return -10.0

        # 2. Penalización para acciones que colapsan u ocultan navegación (ej. "COLAPSAR", "contraer")
        for palabra_colapso in PALABRAS_CLAVE_COLAPSAR:
            if palabra_colapso in texto_completo:
                return -8.0

        # 2b. Penalizar controles de cambio de tema/diseño cosmético
        for palabra_tema in ('tour-theme', 'theme', 'dark-mode', 'darkmode', 'light-mode'):
            if palabra_tema in texto_completo:
                return -6.0

        # --- PRIORIDADES MÁXIMAS ESPECÍFICAS DE IA Y DIAGRAMADOR ---
        # A. Pestaña de Asistente IA en el Diagramador
        if any(k in texto_completo for k in ('asistente ia', 'asistente-ia', 'ia asistente')):
            return 15.0

        # B. Botón "Editar Modelo" o enlaces a diagramas específicos
        if 'editar modelo' in texto_completo or ('editar' in texto_completo and 'modelo' in texto_completo) or (elemento.href and '/diagramas/' in elemento.href):
            return 12.0

        # C. Acceso al Diagramador principal en el menú o navegación
        if 'tour-diagramador' in elemento.selector or (elemento.href and '/diagramas' in elemento.href):
            return 10.0

        # D. Pestaña de Reportes Inteligentes (IA)
        if 'reportes inteligentes' in texto_completo or '(ia)' in texto_completo:
            return 10.0

        # E. Botón de Consultar IA
        if 'consultar ia' in texto_completo or 'consultar' in texto_completo:
            return 8.0

        score = 0.0

        # 3. Detección explícita de IA / Chat / Auditoría
        es_ia_explicita = False
        if any(term in texto_completo for term in (
            ' ia', 'ia ', 'inteligente', 'auditoría', 'auditoria', 'neuronal', 'chat', 'asistente', 'assistant'
        )):
            score += 7.0
            es_ia_explicita = True
        else:
            for palabra in PALABRAS_CLAVE_EXPLORACION:
                if palabra in texto_completo:
                    score += 3.5
                    break

        # 4. Href o selector que apunte a rutas de chat/asistente/ia/diagramas
        if elemento.href:
            href_lower = elemento.href.lower()
            if any(k in href_lower for k in ('chat', 'asistente', 'assistant', 'ai', 'ia', 'talk', 'bot', 'diagram')):
                score += 4.5
            elif elemento.href.startswith(('/', '#')) or not elemento.href.startswith(('http://', 'https://')):
                score += 2.0  # Ruta interna de navegación

        if any(k in elemento.selector.lower() for k in ('chat', 'asistente', 'assistant', 'ai', 'ia', 'bot', 'diagram')):
            score += 3.5

        # 5. Bonus para enlaces de navegación principal del Tour / Sidebar de SPAs
        if elemento.selector.startswith('#tour-') and not any(t in elemento.selector for t in ('theme', 'exit', 'logout')):
            if urls_visitadas and elemento.href:
                path_href = elemento.href.split('?')[0].lower()
                visitada = any(path_href in u.lower() for u in urls_visitadas)
                if not visitada:
                    score += 4.0  # Prioridad para visitar secciones no exploradas
                else:
                    score -= 1.0  # Reducir prioridad de secciones ya visitadas
            else:
                score += 3.0

        # 5b. Priorizar enlaces con rutas no visitadas en general
        if urls_visitadas and elemento.href and elemento.tag_name == 'a':
            path_href = elemento.href.split('?')[0].lower()
            if not any(path_href in u.lower() for u in urls_visitadas):
                score += 2.5

        # 5c. Despriorizar secciones administrativas/secundarias que no contienen IA
        if any(t in texto_completo for t in ('bandeja', 'actualizar bandeja', 'tour-tareas', 'tour-usuarios', 'tour-politicas')):
            score -= 2.0

        # 6. Bonus para acciones de expandir/abrir menú o navegación (hamburguesa, toggle de navegación)
        es_expansor = False
        for palabra_expansion in PALABRAS_CLAVE_EXPANDIR:
            if palabra_expansion in texto_completo:
                score += 2.5
                es_expansor = True
                break

        # 7. Elementos flotantes o widgets
        clases_lower = (elemento.clases or '').lower()
        if any(c in clases_lower for c in ('float', 'widget', 'modal', 'popup', 'toggle', 'drawer')):
            score += 2.0

        # 8. Elementos de navegación en SPAs (menú, nav, mat-list-item, sidebar)
        if any(c in clases_lower for c in ('nav', 'menu', 'sidebar', 'mat-list-item', 'tab')):
            score += 1.8

        # 9. Prioridad por tipo de elemento
        if es_ia_explicita and elemento.tag_name in ('button', 'a', 'div'):
            score += 3.0
        elif elemento.tag_name == 'a' or 'mat-list-item' in elemento.selector:
            score += 2.0
        elif elemento.tag_name == 'button':
            if es_expansor:
                score += 1.0
            else:
                score += 0.5

        return score

    @classmethod
    def _obtener_hash_dom(cls, page: Page) -> str:
        """Genera un hash representativo del estado del DOM para detectar cambios."""
        try:
            # Hash basado en cantidad de inputs, botones y texto estructurado
            info_dom = page.evaluate('''() => {
                const inputs = document.querySelectorAll('input, textarea, [contenteditable="true"]').length;
                const buttons = document.querySelectorAll('button, a').length;
                const modales = document.querySelectorAll('[role="dialog"], .modal, .sidebar, .drawer').length;
                const textSnippet = (document.body ? document.body.innerText : '').slice(0, 500);
                return `${inputs}_${buttons}_${modales}_${textSnippet}`;
            }''')
            return hashlib.md5(info_dom.encode('utf-8', errors='ignore')).hexdigest()
        except Exception:
            return ""

    @classmethod
    def _es_misma_vista(
        cls, 
        hash_anterior: str, 
        hash_actual: str, 
        url_anterior: str, 
        url_actual: str
    ) -> bool:
        """Determina si dos capturas representan el mismo estado visual y de DOM."""
        if url_anterior != url_actual:
            return False
        return hash_anterior == hash_actual

    @classmethod
    def _es_navegacion_interna(cls, url_base: str, url_destino: str) -> bool:
        """Verifica que la URL pertenezca al mismo host/origen que la base analizada."""
        try:
            parsed_base = urllib.parse.urlparse(url_base)
            parsed_destino = urllib.parse.urlparse(url_destino)

            # Esquemas permitidos
            if parsed_destino.scheme and parsed_destino.scheme not in ('http', 'https'):
                return False

            # Si no tiene netloc, es ruta relativa -> pertenece al mismo sitio
            if not parsed_destino.netloc:
                return True

            return parsed_base.netloc.lower() == parsed_destino.netloc.lower()
        except Exception:
            return False

    @classmethod
    def _ejecutar_click_seguro(cls, page: Page, selector: str) -> bool:
        """Intenta hacer clic en el elemento asegurando tolerancia a fallos y espera de navegación."""
        try:
            locator = page.locator(selector).first
            if locator.is_visible():
                locator.click(timeout=4000)
                try:
                    page.wait_for_load_state('domcontentloaded', timeout=2000)
                except Exception:
                    pass
                return True
        except Exception as err:
            logger.debug(f"Click no pudo completarse en {selector}: {err}")
        return False

    @classmethod
    def _intentar_volver_atras(cls, page: Page, url_anterior: str) -> bool:
        """Restaura la navegación previa usando enlaces del sidebar de la SPA o navegación del browser."""
        try:
            # 1. En SPAs, intentar navegar usando los enlaces del sidebar para no recargar ni perder sesión
            path_destino = urllib.parse.urlparse(url_anterior).path
            if path_destino and path_destino != '/':
                for sel in [f'a[href="{path_destino}"]', f'[id*="tour-"][href="{path_destino}"]', f'a[routerlink="{path_destino}"]']:
                    try:
                        loc = page.locator(sel).first
                        if loc.is_visible():
                            loc.click(timeout=2000)
                            page.wait_for_timeout(1000)
                            return True
                    except Exception:
                        pass

            page.go_back(timeout=3000)
            page.wait_for_timeout(1000)
            return True
        except Exception:
            try:
                page.goto(url_anterior, wait_until='domcontentloaded', timeout=5000)
                page.wait_for_timeout(1000)
                return True
            except Exception:
                return False
