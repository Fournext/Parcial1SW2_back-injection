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
    PUNTUACION_MINIMA_INPUT_CONFIABLE,
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

            # Si no hubo botón o el clic falló, intentar buscar botones de acción visibles
            if not click_exitoso:
                for btn_action_text in ['generar', 'enviar', 'send', 'submit', 'generate', 'analizar']:
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
        elementos_ya_probados: Set[str] = set()

        logger.info(
            f"[{EventosLog.EXPLORER_STARTED}] Iniciando exploración activa en {url_base} "
            f"(máx pasos: {max_pasos}, máx prof: {max_profundidad})"
        )

        while estado.pasos_realizados < max_pasos:
            url_antes = page.url
            hash_antes = cls._obtener_hash_dom(page)

            # Descubrir elementos en la vista actual
            elementos = cls._descubrir_elementos_interactivos(page)

            # Filtrar elementos ya probados en este selector o selector idéntico
            elementos_disponibles = [
                elem for elem in elementos if elem.selector not in elementos_ya_probados
            ]

            if not elementos_disponibles:
                logger.info("No hay más elementos interactivos por explorar en la vista actual.")
                # Si estamos en una URL diferente a la base, intentar volver atrás
                if url_antes != url_base and estado.profundidad_actual > 0:
                    cls._intentar_volver_atras(page, url_base)
                    estado.profundidad_actual = max(0, estado.profundidad_actual - 1)
                    continue
                break

            # Tomar el elemento con mayor relevancia
            elem_a_probar = elementos_disponibles[0]
            elementos_ya_probados.add(elem_a_probar.selector)
            estado.elementos_clickeados.append(elem_a_probar.selector)
            estado.pasos_realizados += 1

            logger.info(
                f"[{EventosLog.EXPLORER_CLICK}] Paso #{estado.pasos_realizados}: "
                f"Clic en '{elem_a_probar.texto_visible or elem_a_probar.tag_name}' "
                f"[{elem_a_probar.selector}] (relevancia: {elem_a_probar.puntuacion_relevancia:.1f})"
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
                continue

            # Detectar si hubo cambio de estado significativo
            es_misma = cls._es_misma_vista(hash_antes, hash_despues, url_antes, url_despues)
            estado_par = (url_despues, hash_despues)

            if estado_par in estados_visitados:
                logger.debug(f"[{EventosLog.EXPLORER_LOOP_DETECTED}] Estado ya conocido {estado_par[0]}.")
                if not es_misma and url_despues != url_antes:
                    cls._intentar_volver_atras(page, url_antes)
                continue

            estados_visitados.add(estado_par)

            tipo_cambio = "ninguno"
            if url_despues != url_antes:
                tipo_cambio = "navegacion"
                estado.profundidad_actual += 1
                if url_despues not in estado.urls_visitadas:
                    estado.urls_visitadas.append(url_despues)
                logger.info(f"[{EventosLog.EXPLORER_NAVIGATION}] Nueva URL detectada: {url_despues}")
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

            # Buscar y probar cualquier input no probado en la vista resultante del clic
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

                # Si excedimos profundidad, retroceder
                if estado.profundidad_actual >= max_profundidad:
                    logger.info("Profundidad máxima de navegación alcanzada. Retrocediendo...")
                    cls._intentar_volver_atras(page, url_base)
                    estado.profundidad_actual = 0

        if estado.pasos_realizados >= max_pasos:
            logger.info(f"[{EventosLog.EXPLORER_MAX_STEPS}] Límite de pasos alcanzado ({max_pasos}).")

        logger.info(
            f"[{EventosLog.EXPLORER_FINISHED}] Fin de exploración sin encontrar interfaz confirmada. "
            f"Pasos: {estado.pasos_realizados}, URLs: {len(estado.urls_visitadas)}"
        )
        return None, estado

    @classmethod
    def _descubrir_elementos_interactivos(cls, page: Page) -> List[ElementoInteractivo]:
        """Extrae y califica heurísticamente los elementos clickeables en la vista activa."""
        candidatos: List[ElementoInteractivo] = []

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
                    clases = elem.get_attribute('class') or ''
                    id_attr = elem.get_attribute('id') or ''

                    # Selector preciso
                    if id_attr:
                        selector_especifico = f"#{id_attr}"
                    elif href and tag_name == 'a':
                        # Escapar comillas si hubiera
                        href_limpio = href.replace('"', '\\"')
                        selector_especifico = f"a[href=\"{href_limpio}\"]"
                    else:
                        selector_especifico = f"{selector_base}:nth-of-type({idx + 1})" if ':nth' not in selector_base else selector_base

                    candidato = ElementoInteractivo(
                        selector=selector_especifico,
                        tag_name=tag_name,
                        texto_visible=texto,
                        href=href,
                        aria_label=aria_label,
                        clases=clases,
                    )
                    candidato.puntuacion_relevancia = cls._calcular_relevancia(candidato)
                    candidatos.append(candidato)

            except Exception as err:
                logger.debug(f"Error evaluando selector explorable {selector_base}: {err}")

        # Ordenar por mayor relevancia heurística
        candidatos.sort(key=lambda item: item.puntuacion_relevancia, reverse=True)
        return candidatos

    @classmethod
    def _calcular_relevancia(cls, elemento: ElementoInteractivo) -> float:
        """Puntúa un elemento según su probabilidad de desplegar o llevar a una interfaz de IA."""
        score = 0.0
        texto_completo = f"{elemento.texto_visible} {elemento.aria_label} {elemento.clases} {elemento.href or ''}".lower()

        # Palabras clave explícitas de IA/Chat
        for palabra in PALABRAS_CLAVE_EXPLORACION:
            if palabra in texto_completo:
                score += 3.0
                break

        # Href que apunte a rutas de chat/asistente
        if elemento.href:
            href_lower = elemento.href.lower()
            if any(k in href_lower for k in ('chat', 'asistente', 'assistant', 'ai', 'ia', 'talk')):
                score += 3.5
            elif elemento.href.startswith(('/', '#')):
                score += 1.0  # Ruta interna genérica

        # Elementos flotantes o widgets
        clases_lower = (elemento.clases or '').lower()
        if any(c in clases_lower for c in ('float', 'widget', 'modal', 'popup', 'toggle', 'drawer')):
            score += 2.0

        # Botones tienen prioridad sobre enlaces genéricos
        if elemento.tag_name == 'button':
            score += 1.5
        elif elemento.tag_name == 'a':
            score += 0.5

        # Penalización severa para acciones destructivas o de salida (evitar salir de la app)
        for palabra_peligrosa in (
            'salir', 'exit', 'volver', 'back', 'logout', 'cerrar sesión',
            'cerrar sesion', 'eliminar', 'delete', 'borrar', 'cancelar', 'cancel'
        ):
            if palabra_peligrosa in texto_completo:
                score -= 10.0
                break

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
        """Intenta hacer clic en el elemento asegurando tolerancia a fallos."""
        try:
            locator = page.locator(selector).first
            if locator.is_visible():
                locator.click(timeout=3000)
                return True
        except Exception as err:
            logger.debug(f"Click no pudo completarse en {selector}: {err}")
        return False

    @classmethod
    def _intentar_volver_atras(cls, page: Page, url_anterior: str) -> bool:
        """Restaura la navegación previa usando go_back o navegación directa."""
        try:
            page.go_back(timeout=4000)
            page.wait_for_timeout(1000)
            return True
        except Exception:
            try:
                page.goto(url_anterior, wait_until='domcontentloaded', timeout=5000)
                page.wait_for_timeout(1000)
                return True
            except Exception:
                return False
