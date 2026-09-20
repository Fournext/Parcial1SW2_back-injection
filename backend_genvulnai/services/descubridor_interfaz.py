"""
Servicio para la localización heurística del campo de entrada y botón de envío de IA.
Analiza textareas, inputs de texto, contenteditables y botones relacionados.
"""
import logging
from typing import List, Optional
from playwright.sync_api import Page
from backend_genvulnai.domain.constants import (
    PALABRAS_CLAVE_IA,
    PALABRAS_CLAVE_AUTH_INPUT,
    PALABRAS_CLAVE_AUTH_BOTON
)
from backend_genvulnai.domain.enums import TipoInterfaz, MetodoEnvio
from backend_genvulnai.domain.schemas import ElementoCandidato, ResultadoInterfaz

logger = logging.getLogger('backend_genvulnai')


class DescubridorInterfazService:
    """Aplica heurísticas sobre el DOM para descubrir la interfaz interactiva de la IA."""

    # Selectores CSS iniciales a evaluar
    SELECTORES_INPUTS = [
        'textarea',
        'input[type="text"]',
        'input:not([type])',
        '[contenteditable="true"]',
        '[role="textbox"]',
        'div[id*="chat" i] input',
        'div[id*="chat" i] textarea',
    ]

    SELECTORES_BOTONES = [
        'button[type="submit"]',
        'button',
        'input[type="submit"]',
        '[role="button"]',
        'form button',
        'svg[data-icon*="send" i]',
        'button:has(svg)'
    ]

    @classmethod
    def obtener_candidatos_entrada(cls, page: Page) -> List[ElementoCandidato]:
        """Extrae y califica heurísticamente los elementos de entrada en la página."""
        return cls._encontrar_candidatos_entrada(page)

    @classmethod
    def construir_resultado_desde_candidato(
        cls, 
        page: Page, 
        candidato: ElementoCandidato, 
        total_candidatos: int
    ) -> ResultadoInterfaz:
        """Construye un ResultadoInterfaz a partir del elemento seleccionado."""
        tipo = TipoInterfaz.CHAT
        if candidato.tag_name == 'div' and candidato.es_editable:
            tipo = TipoInterfaz.EDITOR
        elif candidato.tag_name == 'input':
            tipo = TipoInterfaz.FORMULARIO

        mejor_boton = cls._encontrar_boton_envio(page, candidato.selector)

        return ResultadoInterfaz(
            tipo=tipo,
            selector_entrada=candidato.selector,
            selector_envio=mejor_boton.selector if mejor_boton else None,
            metodo_envio=MetodoEnvio.BOTON if mejor_boton else MetodoEnvio.ENTER,
            candidatos_evaluados=total_candidatos
        )

    @classmethod
    def descubrir_interfaz(cls, page: Page) -> ResultadoInterfaz:
        """
        Escanea la página, puntúa los elementos candidatos y retorna la mejor combinación.
        Descarta formularios que pertenezcan a pantallas de autenticación o login.
        """
        candidatos_input = cls.obtener_candidatos_entrada(page)
        candidatos_validos = [c for c in candidatos_input if c.puntuacion > 0]
        
        if not candidatos_validos:
            logger.info("No se encontraron campos de entrada válidos para IA (descartados campos de login o no interactivos).")
            return ResultadoInterfaz(
                tipo=TipoInterfaz.DESCONOCIDO,
                selector_entrada=None,
                selector_envio=None,
                metodo_envio=MetodoEnvio.DESCONOCIDO,
                candidatos_evaluados=len(candidatos_input)
            )

        # Ordenar por puntuación descendente
        candidatos_validos.sort(key=lambda c: c.puntuacion, reverse=True)
        return cls.construir_resultado_desde_candidato(page, candidatos_validos[0], len(candidatos_validos))


    @classmethod
    def _encontrar_candidatos_entrada(cls, page: Page) -> List[ElementoCandidato]:
        """Extrae y califica heurísticamente los elementos de entrada en la página."""
        candidatos: List[ElementoCandidato] = []

        for selector_base in cls.SELECTORES_INPUTS:
            try:
                elementos = page.locator(selector_base).all()
                for idx, elem in enumerate(elementos):
                    if not elem.is_visible():
                        continue

                    tag_name = elem.evaluate('el => el.tagName.toLowerCase()')
                    tipo_input = (elem.get_attribute('type') or '').lower()
                    
                    # Descartar inputs de contraseña, ocultos o selecciones
                    if tipo_input in ('password', 'hidden', 'checkbox', 'radio', 'file'):
                        continue

                    placeholder = elem.get_attribute('placeholder') or ''
                    aria_label = elem.get_attribute('aria-label') or ''
                    name_attr = elem.get_attribute('name') or ''
                    id_attr = elem.get_attribute('id') or ''
                    autocomplete_attr = elem.get_attribute('autocomplete') or ''
                    is_editable = elem.is_editable()

                    # Descartar completamente campos típicos de inicio de sesión o credenciales
                    texto_completo = f"{placeholder} {aria_label} {name_attr} {id_attr} {autocomplete_attr}".lower()
                    if any(auth_kw in texto_completo for auth_kw in PALABRAS_CLAVE_AUTH_INPUT):
                        logger.debug(f"Descartando input de autenticación: {name_attr or id_attr or placeholder}")
                        continue

                    # Generar selector CSS robusto
                    selector_especifico = cls._construir_selector(tag_name, id_attr, name_attr, selector_base, idx)

                    # Puntuación heurística
                    score = 1.0

                    if tag_name == 'textarea':
                        score += 3.0  # Los textareas son predilectos en interfaces LLM/Chat

                    for palabra in PALABRAS_CLAVE_IA:
                        if palabra in texto_completo:
                            score += 2.0

                    candidatos.append(ElementoCandidato(
                        selector=selector_especifico,
                        tag_name=tag_name,
                        tipo_elemento='textarea' if tag_name == 'textarea' else 'input',
                        puntuacion=score,
                        placeholder=placeholder,
                        aria_label=aria_label,
                        es_editable=is_editable
                    ))
            except Exception as err:
                logger.debug(f"Aviso evaluando selector {selector_base}: {err}")

        return candidatos

    @classmethod
    def _encontrar_boton_envio(cls, page: Page, selector_input: str) -> Optional[ElementoCandidato]:
        """Encuentra el botón de envío asociado o más cercano al campo de entrada."""
        candidatos_botones: List[ElementoCandidato] = []

        # Obtener contenedor padre del input si es posible para medir proximidad
        input_elem = None
        try:
            input_elem = page.locator(selector_input).first
        except Exception:
            pass

        for selector_btn in cls.SELECTORES_BOTONES:
            try:
                botones = page.locator(selector_btn).all()
                for idx, btn in enumerate(botones):
                    if not btn.is_visible():
                        continue

                    tag_name = btn.evaluate('el => el.tagName.toLowerCase()')
                    texto = btn.inner_text().strip()
                    aria_label = btn.get_attribute('aria-label') or ''
                    role_attr = (btn.get_attribute('role') or '').lower()
                    tipo_btn = btn.get_attribute('type') or ''
                    id_attr = btn.get_attribute('id') or ''

                    # Penalizar pestañas o tabs que cambian de sección, no envían
                    if role_attr == 'tab' or any(t in texto.lower() for t in ('reportes inteligentes', 'asistente ia', 'métricas', 'metricas', 'bandeja')):
                        continue

                    score = 1.0
                    if tipo_btn == 'submit':
                        score += 3.0

                    texto_combinado = f"{texto} {aria_label} {id_attr}".lower()

                    # Bonificación especial para verbos de generación, consulta y envío
                    if any(v in texto_combinado for v in ('consultar ia', 'consultar', 'generar', 'generate', 'enviar', 'send', 'submit', 'analizar', 'ejecutar', 'preguntar')):
                        score += 4.0

                    for palabra in PALABRAS_CLAVE_IA:
                        if palabra in texto_combinado:
                            score += 2.0

                    # Botón con SVG (típico icono de enviar o avión en chats)
                    tiene_svg = False
                    try:
                        tiene_svg = btn.locator('svg').count() > 0
                    except Exception:
                        pass
                    if tiene_svg:
                        score += 2.0

                    # Proximidad: verificar si está en el mismo contenedor padre
                    if input_elem:
                        try:
                            es_cercano = btn.evaluate(
                                '(btn, input) => btn.closest("form, div, section") === input.closest("form, div, section")',
                                input_elem.element_handle()
                            )
                            if es_cercano:
                                score += 3.5
                        except Exception:
                            pass

                    # Penalizar botones de navegación/salida
                    if any(v in texto_combinado for v in ('salir', 'exit', 'volver', 'back', 'cancelar', 'cerrar')):
                        score -= 10.0

                    # Penalizar severamente botones de login/autenticación
                    if any(v in texto_combinado for v in PALABRAS_CLAVE_AUTH_BOTON):
                        score -= 20.0

                    # Si el botón tiene texto visible claro y breve, usar selector de texto
                    if texto and len(texto) <= 30 and not id_attr:
                        primer_linea = texto.split('\n')[0].strip().replace('"', '\\"')
                        if primer_linea:
                            selector_especifico = f'button:has-text("{primer_linea}")'
                        else:
                            selector_especifico = cls._construir_selector(tag_name, id_attr, '', selector_btn, idx)
                    else:
                        selector_especifico = cls._construir_selector(tag_name, id_attr, '', selector_btn, idx)

                    candidatos_botones.append(ElementoCandidato(
                        selector=selector_especifico,
                        tag_name=tag_name,
                        tipo_elemento='boton',
                        puntuacion=score,
                        texto_visible=texto,
                        aria_label=aria_label
                    ))
            except Exception as err:
                logger.debug(f"Aviso buscando botones: {err}")

        if candidatos_botones:
            candidatos_botones.sort(key=lambda b: b.puntuacion, reverse=True)
            return candidatos_botones[0]

        return None

    @classmethod
    def _construir_selector(cls, tag: str, id_attr: str, name_attr: str, selector_base: str, index: int) -> str:
        """Construye un selector CSS específico y reproducible."""
        if id_attr:
            return f"#{id_attr}"
        if name_attr:
            return f"{tag}[name='{name_attr}']"
        return f"{selector_base}:nth-of-type({index + 1})" if ':nth' not in selector_base else selector_base
