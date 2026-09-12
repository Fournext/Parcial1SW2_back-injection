"""
Orquestador principal del proceso de descubrimiento de interacción con IA.
Coordina secuencialmente la navegación, detección de interfaz, inyección del marcador,
análisis de tráfico HTTP/WebSocket, resolución semántica con IA (Ollama), cálculo de confianza y persistencia.
"""
import os
import uuid
import time
import logging
import threading
from typing import Dict, Any, Optional
from django.conf import settings

# Permitir operaciones síncronas del ORM en hilos que ejecutan o hayan ejecutado Playwright
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"

from backend_genvulnai.domain.constants import (
    PREFIJO_MARCADOR, 
    EventosLog, 
    PESO_HEURISTICA, 
    PESO_IA, 
    UMBRAL_DIFERENCIA_CANDIDATOS
)
from backend_genvulnai.domain.enums import MetodoEnvio, ModoEntrada, ModoRespuesta
from backend_genvulnai.domain.schemas import ResultadoCanal, EstadoExploracion
from backend_genvulnai.services.validador_url import ValidadorURLService
from backend_genvulnai.services.navegador import NavegadorService
from backend_genvulnai.services.capturador_red import CapturadorRedService
from backend_genvulnai.services.descubridor_interfaz import DescubridorInterfazService
from backend_genvulnai.services.explorador_dom import ExploradorDOMService
from backend_genvulnai.services.detector_canal import DetectorCanalService
from backend_genvulnai.services.detector_websocket import DetectorWebSocketService
from backend_genvulnai.services.detector_autenticacion import DetectorAutenticacionService
from backend_genvulnai.services.calculador_confianza import CalculadorConfianzaService
from backend_genvulnai.services.analizador_ia import AnalizadorIA
from backend_genvulnai.repositories.descubrimiento_repository import DescubrimientoRepository
from backend_genvulnai.exceptions import DescubrimientoError, URLNoPermitidaError

logger = logging.getLogger('backend_genvulnai')


class OrquestadorDescubrimientoService:
    """Ejecuta el ciclo de vida completo del escaneo de descubrimiento."""

    @classmethod
    def iniciar_escaneo_asincrono(cls, scan_id: str, url_objetivo: str) -> None:
        """Lanza el análisis en un hilo independiente para no bloquear la petición HTTP."""
        hilo = threading.Thread(
            target=cls.ejecutar_escaneo,
            args=(scan_id, url_objetivo),
            daemon=True
        )
        hilo.start()

    @classmethod
    def ejecutar_escaneo(
        cls, 
        scan_id: str, 
        url_objetivo: str,
        analizador_ia: Optional[AnalizadorIA] = None
    ) -> Dict[str, Any]:
        """
        Ejecuta secuencialmente todas las fases del descubrimiento,
        incorporando análisis semántico con Ollama cuando se detecta ambigüedad.
        """
        # Configuración de IA local (Ollama)
        cfg_ollama = getattr(settings, 'OLLAMA', {})
        ollama_habilitada = cfg_ollama.get('ENABLED', True)
        min_confianza_heuristica = float(cfg_ollama.get('MIN_HEURISTIC_CONFIDENCE', 0.80))
        modelo_nombre = cfg_ollama.get('MODEL', 'llama3.2')
        
        analizador = analizador_ia or AnalizadorIA()
        ollama_disponible = analizador.esta_disponible() if ollama_habilitada else False
        
        se_uso_ia = False
        detalle_interfaz_ia: Optional[str] = None
        detalle_canal_ia: Optional[str] = None

        # Generar marcador único para esta sesión de prueba
        token_aleatorio = uuid.uuid4().hex[:8]
        marcador = f"{PREFIJO_MARCADOR}{token_aleatorio}"

        logger.info(f"[{EventosLog.SCAN_STARTED}] Iniciando escaneo {scan_id} sobre {url_objetivo} con marcador {marcador}")
        DescubrimientoRepository.iniciar_escaneo(scan_id, marcador)

        scan_model = DescubrimientoRepository.obtener_por_id(scan_id)

        try:
            # FASE 1: Validación estricta y protección SSRF
            ValidadorURLService.validar_url(url_objetivo)

            # Variables recolectadas durante la navegación
            hubo_cambio_ui = False
            metodo_utilizado = MetodoEnvio.DESCONOCIDO
            resultado_interfaz = None
            estado_exploracion: Optional[EstadoExploracion] = None
            observaciones_http = []
            observaciones_ws = []

            # FASE 2: Navegación y captura de red con Playwright
            with NavegadorService() as navegador:
                capturador = CapturadorRedService()
                page = navegador.obtener_pagina()
                
                # FASE 5: Iniciar captura de red y eventos
                capturador.vincular_eventos(page)

                logger.info(f"[{EventosLog.PAGE_LOADED}] Navegando hacia {url_objetivo}")
                navegador.navegar(url_objetivo)

                # FASE 3: Descubrimiento y exploración activa con validación de red
                max_pasos_exp = getattr(settings, 'MAX_EXPLORATION_STEPS', 25)
                max_prof_exp = getattr(settings, 'MAX_EXPLORATION_DEPTH', 3)
                
                resultado_explorado, estado_exp = ExploradorDOMService.explorar_hasta_encontrar_interfaz(
                    page=page,
                    url_base=url_objetivo,
                    marcador=marcador,
                    capturador=capturador,
                    max_pasos=max_pasos_exp,
                    max_profundidad=max_prof_exp,
                )
                estado_exploracion = estado_exp

                marcador_ya_enviado = False
                if resultado_explorado and resultado_explorado.selector_entrada:
                    resultado_interfaz = resultado_explorado
                    marcador_ya_enviado = True
                    logger.info(
                        f"[{EventosLog.AI_INPUT_FOUND}] Interfaz detectada y confirmada en red: tipo={resultado_interfaz.tipo}, "
                        f"input={resultado_interfaz.selector_entrada}, boton={resultado_interfaz.selector_envio}"
                    )
                else:
                    # Si la exploración interactiva no confirmó ningún input mediante red, fallback a heurística
                    resultado_interfaz = DescubridorInterfazService.descubrir_interfaz(page)
                    logger.info(
                        f"[{EventosLog.AI_INPUT_FOUND}] No se confirmó interfaz mediante sondeo interactivo. "
                        f"Resultado fallback: input={resultado_interfaz.selector_entrada}"
                    )

                # FASE 6: Enviar el marcador (solo si no fue enviado y confirmado durante la exploración)
                metodo_utilizado = resultado_interfaz.metodo_envio

                if not marcador_ya_enviado and resultado_interfaz.selector_entrada:
                    try:
                        input_loc = page.locator(resultado_interfaz.selector_entrada).first
                        input_loc.click()
                        input_loc.fill(marcador)
                        page.wait_for_timeout(500)

                        click_exitoso = False
                        if resultado_interfaz.selector_envio:
                            btn_loc = page.locator(resultado_interfaz.selector_envio).first
                            if btn_loc.is_visible():
                                try:
                                    btn_loc.click(timeout=2000)
                                    metodo_utilizado = MetodoEnvio.BOTON
                                    click_exitoso = True
                                except Exception:
                                    pass

                        if not click_exitoso:
                            for btn_action_text in ['generar', 'enviar', 'send', 'submit', 'generate', 'analizar']:
                                try:
                                    btn_action = page.locator(f'button:has-text("{btn_action_text}")').first
                                    if btn_action.is_visible():
                                        btn_action.click(timeout=2000)
                                        metodo_utilizado = MetodoEnvio.BOTON
                                        click_exitoso = True
                                        break
                                except Exception:
                                    pass

                        if not click_exitoso:
                            if 'textarea' in resultado_interfaz.selector_entrada:
                                try:
                                    input_loc.press("Control+Enter")
                                except Exception:
                                    pass
                                input_loc.press("Enter")
                            else:
                                input_loc.press("Enter")
                            metodo_utilizado = MetodoEnvio.ENTER

                        logger.info(f"[{EventosLog.MARKER_SENT}] Marcador {marcador} inyectado mediante {metodo_utilizado}")
                    except Exception as err_envio:
                        logger.warning(f"Aviso intentando interactuar con la interfaz: {err_envio}")

                # Espera de red tras el envío para capturar respuestas asíncronas o SSE
                page.wait_for_timeout(3000)

                # Comprobar si hubo cambios visibles en la UI
                try:
                    contenido_pagina = page.content()
                    hubo_cambio_ui = marcador in contenido_pagina or "asistente" in contenido_pagina.lower()
                except Exception:
                    hubo_cambio_ui = False

                # Extraer observaciones antes de cerrar el navegador
                observaciones_http = capturador.obtener_observaciones_http()
                observaciones_ws = capturador.obtener_observaciones_ws()

            # FIN DE FASE 2: El navegador y su bucle async se han cerrado limpiamente

            # FASE 7 y 8: Encontrar el canal HTTP candidato y evaluar ambigüedades
            candidatos_http = DetectorCanalService.obtener_candidatos_evaluados(observaciones_http, marcador)

            # FASE 13: Evaluar WebSockets
            canal_ws = DetectorWebSocketService.analizar_conexiones(observaciones_ws, marcador)

            canal_http = None
            confianza_ia_canal: Optional[float] = None

            if not canal_ws and candidatos_http:
                mejor_score, mejor_obs = candidatos_http[0]

                # Si el mejor candidato tiene coincidencia definitiva y marcador exacto -> ruta determinista
                if mejor_score >= 0.95 and mejor_obs.contiene_marcador:
                    logger.info(
                        f"[{EventosLog.OLLAMA_SKIPPED_HIGH_CONFIDENCE}] Coincidencia determinante con marcador exacto (score={mejor_score}). Omitiendo IA."
                    )
                    canal_http = DetectorCanalService.construir_canal_desde_observacion(mejor_obs, marcador)
                elif mejor_score <= 0.20:
                    logger.info("No se encontró ningún candidato HTTP con suficiente confianza base.")
                    canal_http = None
                else:
                    # Evaluar si la situación es ambigua
                    diferencia_top = 1.0
                    if len(candidatos_http) > 1:
                        diferencia_top = mejor_score - candidatos_http[1][0]

                    es_ambiguo = (mejor_score < min_confianza_heuristica) or (diferencia_top < UMBRAL_DIFERENCIA_CANDIDATOS)

                    if es_ambiguo and ollama_disponible:
                        logger.info(
                            f"[{EventosLog.OLLAMA_CALL_STARTED}] Ambigüedad en tráfico HTTP (score={mejor_score}, dif={diferencia_top:.2f}). Consultando Ollama."
                        )
                        obs_dicts = [
                            {
                                "protocolo": "HTTP",
                                "metodo": obs.metodo,
                                "url": obs.url,
                                "status_code": obs.response_status or 0,
                                "content_type": obs.response_content_type or obs.headers_sanitizados.get('content-type', ''),
                                "contiene_marcador": obs.contiene_marcador,
                                "body_preview": obs.body_original or ""
                            }
                            for _, obs in candidatos_http[:10]
                        ]
                        analisis_c = analizador.seleccionar_canal(obs_dicts, marcador)
                        if analisis_c and not analisis_c.evidencia_insuficiente and analisis_c.indice_seleccionado is not None:
                            obs_elegida = candidatos_http[analisis_c.indice_seleccionado][1]
                            canal_http = DetectorCanalService.construir_canal_desde_observacion(obs_elegida, marcador)

                            # Complementar detalles si la heurística no los tenía
                            if analisis_c.campo_prompt and not canal_http.campo_prompt:
                                canal_http.campo_prompt = analisis_c.campo_prompt
                            if analisis_c.modo_entrada and canal_http.modo_entrada == ModoEntrada.DESCONOCIDO:
                                canal_http.modo_entrada = analisis_c.modo_entrada
                            if analisis_c.modo_respuesta and canal_http.modo_respuesta == ModoRespuesta.DESCONOCIDO:
                                canal_http.modo_respuesta = analisis_c.modo_respuesta

                            confianza_ia_canal = analisis_c.confianza_ia
                            se_uso_ia = True
                            detalle_canal_ia = analisis_c.justificacion
                            logger.info(
                                f"[{EventosLog.OLLAMA_CALL_SUCCESS}] Ollama seleccionó canal #{analisis_c.indice_seleccionado}: {analisis_c.justificacion}"
                            )
                        else:
                            logger.info(f"[{EventosLog.OLLAMA_FALLBACK_TRIGGERED}] Fallback a heurística principal para canal HTTP.")
                            canal_http = DetectorCanalService.construir_canal_desde_observacion(mejor_obs, marcador)
                    else:
                        canal_http = DetectorCanalService.construir_canal_desde_observacion(mejor_obs, marcador)

            # Canal final elegido
            canal_final: Optional[ResultadoCanal] = canal_ws if canal_ws else canal_http
            observacion_asociada = None

            if canal_final:
                if canal_final.es_websocket:
                    logger.info(f"[{EventosLog.WEBSOCKET_MATCHED}] Canal WebSocket identificado: {canal_final.url}")
                else:
                    logger.info(f"[{EventosLog.REQUEST_MATCHED}] Canal HTTP identificado: {canal_final.metodo} {canal_final.url}")
                    for obs in observaciones_http:
                        if obs.url == canal_final.url and obs.metodo == canal_final.metodo:
                            observacion_asociada = obs
                            break

            # FASE 10: Detección de autenticación
            headers_a_analizar = observacion_asociada.headers_sanitizados if observacion_asociada else {}
            resultado_auth = DetectorAutenticacionService.analizar_autenticacion(headers_a_analizar)
            if resultado_auth.requerida:
                logger.info(f"[{EventosLog.AUTH_DETECTED}] Autenticación detectada: {resultado_auth.tipos}")

            # FASE 15: Cálculo y combinación de nivel de confianza
            confianza = CalculadorConfianzaService.calcular_confianza(
                canal=canal_final,
                observacion_asociada=observacion_asociada,
                hubo_cambio_en_ui=hubo_cambio_ui
            )

            if confianza_ia_canal is not None:
                confianza = CalculadorConfianzaService.combinar_scores(
                    score_heuristico=confianza,
                    score_ia=confianza_ia_canal,
                    peso_heuristica=PESO_HEURISTICA,
                    peso_ia=PESO_IA
                )
                logger.info(f"[{EventosLog.OLLAMA_COMBINED_SCORE}] Confianza combinada con IA: {confianza}")

            # FASE 16: Estructura del resultado consolidado
            payload_canal = None
            if canal_final:
                payload_canal = {
                    "protocolo": canal_final.protocolo,
                    "transporte": canal_final.transporte,
                    "url": canal_final.url,
                    "metodo": canal_final.metodo,
                    "content_type": canal_final.content_type,
                    "entrada": {
                        "modo": canal_final.modo_entrada,
                        "campo": canal_final.campo_prompt
                    },
                    "respuesta": {
                        "modo": canal_final.modo_respuesta
                    }
                }

            resultado_completo = {
                "objetivo": {
                    "url": url_objetivo,
                    "accesible": True
                },
                "interfaz": {
                    "tipo": resultado_interfaz.tipo if resultado_interfaz else "desconocido",
                    "selector_entrada": resultado_interfaz.selector_entrada if resultado_interfaz else None,
                    "selector_envio": resultado_interfaz.selector_envio if resultado_interfaz else None,
                    "metodo_envio": metodo_utilizado
                },
                "canal": payload_canal,
                "autenticacion": {
                    "requerida": resultado_auth.requerida,
                    "tipos": resultado_auth.tipos,
                    "cookies": resultado_auth.cookies,
                    "headers": resultado_auth.headers
                },
                "confianza": confianza,
                "marcador_utilizado": marcador,
                "observaciones_registradas": len(observaciones_http),
                "ia_local": {
                    "habilitada": ollama_habilitada,
                    "disponible": ollama_disponible,
                    "modelo": modelo_nombre,
                    "usada": se_uso_ia,
                    "justificacion_interfaz": detalle_interfaz_ia,
                    "justificacion_canal": detalle_canal_ia
                },
                "exploracion": {
                    "realizada": estado_exploracion is not None,
                    "pasos_realizados": estado_exploracion.pasos_realizados if estado_exploracion else 0,
                    "urls_visitadas": estado_exploracion.urls_visitadas if estado_exploracion else [url_objetivo],
                    "interfaz_encontrada": estado_exploracion.interfaz_encontrada if estado_exploracion else (resultado_interfaz.selector_entrada is not None if resultado_interfaz else False),
                    "elementos_probados": len(estado_exploracion.elementos_clickeados) if estado_exploracion else 0,
                    "ruta_hasta_interfaz": estado_exploracion.ruta_hasta_interfaz if estado_exploracion else []
                }
            }

            # FASE 17: Persistencia en Base de Datos
            if scan_model:
                if canal_final:
                    DescubrimientoRepository.guardar_canal(
                        scan=scan_model,
                        canal=canal_final,
                        tipo_interfaz=resultado_interfaz.tipo if resultado_interfaz else "desconocido",
                        autenticacion_requerida=resultado_auth.requerida,
                        tipos_autenticacion=resultado_auth.tipos,
                        confianza=confianza
                    )
                DescubrimientoRepository.guardar_observaciones(scan_model, observaciones_http)
                DescubrimientoRepository.actualizar_metadatos_ia(
                    scan_id=scan_id,
                    ia_habilitada=ollama_habilitada,
                    ia_utilizada=se_uso_ia,
                    ia_modelo=modelo_nombre if se_uso_ia else ""
                )
                DescubrimientoRepository.completar_escaneo(scan_id, resultado_completo)

            logger.info(f"[{EventosLog.SCAN_FINISHED}] Escaneo {scan_id} finalizado exitosamente. Confianza: {confianza}")
            return resultado_completo

        except URLNoPermitidaError as err_url:
            msg = f"URL rechazada por política de seguridad: {err_url}"
            logger.warning(f"[{EventosLog.SCAN_FAILED}] {msg}")
            DescubrimientoRepository.fallar_escaneo(scan_id, msg)
            return {"error": msg}

        except Exception as err:
            msg = f"Fallo no controlado durante el escaneo: {err}"
            logger.error(f"[{EventosLog.SCAN_FAILED}] {msg}", exc_info=True)
            DescubrimientoRepository.fallar_escaneo(scan_id, msg)
            return {"error": msg}
