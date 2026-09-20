"""
Orquestador principal del ciclo de ataque automatizado y red-teaming (A1 -> D1 -> J1).
Coordina la interacción entre el Agente Atacante A1, el Ejecutor de Transporte HTTP y el Juez Evaluador J1.
"""
import logging
import threading
import time
from typing import Optional, Dict, Any
from django.conf import settings
from django.utils import timezone

from backend_genvulnai.domain.enums import EstadoAtaque, EstadoEscaneo
from backend_genvulnai.domain.constants import (
    EventosLog,
    MAX_TURNOS_ATAQUE_DEFAULT,
    MODELO_J1_DEFAULT,
    PUNTAJE_EXITO,
    PUNTAJE_ACTIVACION_PERSISTENCIA,
    TURNOS_REFUERZO_DEFAULT,
    TURNOS_VERIFICACION_PERSISTENCIA,
    MAX_REINTENTOS_TRANSPORTE,
    ESPERA_RATE_LIMIT_BASE,
)
from backend_genvulnai.domain.schemas import (
    ConfiguracionPersistencia,
    ConfiguracionTransporte,
    ResultadoPersistencia,
    ResultadoSesionAtaque,
    ResultadoTurnoAtaque,
)
from backend_genvulnai.models import AttackSession, DiscoveryScan, AIChannel
from backend_genvulnai.repositories.ataque_repository import AtaqueRepository
from backend_genvulnai.repositories.descubrimiento_repository import DescubrimientoRepository
from backend_genvulnai.services.agente_a1 import AgenteA1, PerfiladorD1
from backend_genvulnai.services.juez_evaluador import JuezEvaluador
from backend_genvulnai.services.ejecutor_transporte import EjecutorTransporte
from backend_genvulnai.services.motor_persistencia import MotorPersistencia
from backend_genvulnai.exceptions import AtaqueError

logger = logging.getLogger('backend_genvulnai')


class OrquestadorAtaqueService:
    """Coordina el bucle continuo de ataque, transporte y evaluación."""

    @classmethod
    def iniciar_ataque_asincrono(
        cls,
        scan_id: str,
        objetivo: str,
        max_turnos: Optional[int] = None,
        persistencia: bool = False,
        vectores_persistencia: Optional[list] = None,
        turnos_refuerzo: Optional[int] = None,
        turnos_verificacion: Optional[int] = None,
    ) -> AttackSession:
        """
        Valida el escaneo origen, prepara la sesión de ataque y dispara el ciclo en segundo plano.
        """
        scan = DescubrimientoRepository.obtener_por_id(scan_id)
        if not scan:
            raise AtaqueError(f"No se encontró ningún escaneo con ID {scan_id}")

        if scan.status != EstadoEscaneo.COMPLETADO:
            raise AtaqueError(
                f"El escaneo {scan_id} se encuentra en estado '{scan.status}'. "
                f"Debe estar en estado '{EstadoEscaneo.COMPLETADO}' para iniciar un ataque."
            )

        # Determinar límite de turnos
        limite_turnos = max_turnos if max_turnos and max_turnos > 0 else getattr(settings, 'ATTACK_MAX_TURNS', MAX_TURNOS_ATAQUE_DEFAULT)
        modelo_a1 = getattr(settings, 'ATTACK_A1_MODEL', getattr(settings, 'OLLAMA', {}).get('MODEL', 'llama3.2'))
        modelo_j1 = getattr(settings, 'ATTACK_J1_MODEL', MODELO_J1_DEFAULT)

        # Configuración de turnos de persistencia
        t_refuerzo = turnos_refuerzo if turnos_refuerzo and turnos_refuerzo > 0 else TURNOS_REFUERZO_DEFAULT
        t_verif = turnos_verificacion if turnos_verificacion and turnos_verificacion > 0 else TURNOS_VERIFICACION_PERSISTENCIA

        # Crear sesión persistente
        sesion = AtaqueRepository.crear_sesion(
            scan_id=scan_id,
            objetivo=objetivo,
            max_turnos=limite_turnos,
            modelo_a1=modelo_a1,
            modelo_j1=modelo_j1,
            persistencia_habilitada=persistencia,
            vectores_persistencia=vectores_persistencia or ([1, 2, 3] if persistencia else []),
            persistencia_turnos_refuerzo=t_refuerzo,
            persistencia_turnos_verificacion=t_verif,
        )

        logger.info(
            f"[{EventosLog.ATTACK_SESSION_STARTED}] Sesión de ataque {sesion.id} creada. "
            f"Objetivo: '{objetivo[:60]}...' Max turnos: {limite_turnos} Persistencia: {persistencia}"
        )

        # Iniciar ejecución en hilo demonio
        hilo = threading.Thread(
            target=cls.ejecutar_ciclo_ataque,
            args=(str(sesion.id),),
            daemon=True,
            name=f"AttackThread-{sesion.id}"
        )
        hilo.start()

        return sesion

    @classmethod
    def ejecutar_ciclo_ataque(cls, session_id: str) -> ResultadoSesionAtaque:
        """
        Ejecuta sincrónicamente el bucle iterativo de ataques hasta lograr el objetivo (10/10)
        o agotar el límite de turnos configurado.
        """
        sesion = AtaqueRepository.obtener_sesion(session_id)
        if not sesion:
            logger.error(f"No se encontró la sesión de ataque {session_id} para ejecución.")
            return ResultadoSesionAtaque(
                session_id=session_id,
                scan_id="",
                objetivo="",
                turnos_ejecutados=0,
                max_turnos=0,
                puntaje_maximo=0,
                exito=False,
                error=f"Sesión {session_id} no encontrada"
            )

        AtaqueRepository.iniciar_sesion(session_id)
        scan = sesion.scan
        objetivo = sesion.objetivo

        logger.info(f"[{EventosLog.ATTACK_SESSION_STARTED}] Iniciando ciclo para sesión {session_id}")

        try:
            # 1. Resolver canal objetivo y transporte
            config_transporte = cls._resolver_configuracion_transporte(scan)
            logger.info(
                f"Canal resuelto para D1: {config_transporte.metodo} {config_transporte.url} "
                f"(campo_prompt={config_transporte.campo_prompt}, cookies={len(config_transporte.cookies)})"
            )

            # 2. Inicializar agentes y perfilador dinámico
            agente_a1 = AgenteA1(
                objetivo=objetivo,
                modelo_override=sesion.modelo_a1
            )
            juez_j1 = JuezEvaluador(
                modelo_override=sesion.modelo_j1
            )
            perfilador_d1 = PerfiladorD1()

            # Variables de ciclo
            puntaje_anterior: Optional[int] = None
            respuesta_anterior_d1: Optional[str] = None
            max_turnos = sesion.max_turnos
            turnos_completados = []
            exito_total = False

            # Variables de persistencia
            config_persistencia = ConfiguracionPersistencia(
                habilitada=sesion.persistencia_habilitada,
                vectores=sesion.vectores_persistencia or [1, 2, 3],
                turnos_refuerzo=sesion.persistencia_turnos_refuerzo or TURNOS_REFUERZO_DEFAULT,
                turnos_verificacion=sesion.persistencia_turnos_verificacion or TURNOS_VERIFICACION_PERSISTENCIA
            )
            resultado_persistencia: Optional[ResultadoPersistencia] = None
            persistencia_intentada = False

            # 3. Bucle interactivo A1 -> D1 -> J1
            numero_turno = 1
            while numero_turno <= max_turnos:
                logger.info(f"[{EventosLog.ATTACK_TURN_STARTED}] --- Turno {numero_turno}/{max_turnos} ---")

                # Paso A: A1 genera prompt adaptado al perfil dinámico
                prompt_a1, tactica, fue_reset = agente_a1.generar_ataque(
                    puntaje_anterior=puntaje_anterior,
                    respuesta_anterior_d1=respuesta_anterior_d1
                )
                logger.info(f"[{EventosLog.ATTACK_PROMPT_GENERATED}] A1 generó prompt ({len(prompt_a1)} chars, táctica={tactica})")

                # Paso B: EjecutorTransporte envía a D1
                max_reintentos_transporte = getattr(settings, 'ATTACK_MAX_REINTENTOS_TRANSPORTE', 1)
                resp_d1 = None

                for intento in range(max_reintentos_transporte + 1):
                    logger.info(f"[{EventosLog.ATTACK_SENT_TO_D1}] Despachando a D1 (intento {intento + 1}/{max_reintentos_transporte + 1})...")
                    resp_d1 = EjecutorTransporte.enviar(config_transporte, prompt_a1)
                    logger.info(
                        f"[{EventosLog.ATTACK_D1_RESPONSE}] D1 respondió status={resp_d1.status_code} "
                        f"en {resp_d1.latencia_ms}ms (longitud={len(resp_d1.texto)})"
                    )

                    # Si la respuesta fue exitosa o es un rechazo ético de modelo, no reintentar
                    if resp_d1.status_code < 400:
                        break

                    texto_lower = resp_d1.texto.lower()
                    patrones_refusal = [
                        "no puedo generar", "no puedo responder", "lo siento, no puedo", "lo siento",
                        "promover el odio", "discriminación", "acoso", "política de seguridad"
                    ]
                    if any(p in texto_lower for p in patrones_refusal):
                        break

                    # Reintento breve de cortesía si es rate-limit o 503
                    es_error_transitorio = (
                        resp_d1.status_code in (429, 503)
                        or any(kw in texto_lower for kw in ["429", "too many requests", "quota", "overloaded"])
                    )
                    if es_error_transitorio and intento < max_reintentos_transporte:
                        time.sleep(2)
                    else:
                        break

                # Registrar respuesta en perfilador dinámico y agente A1
                perfilador_d1.registrar_respuesta(resp_d1.texto)
                agente_a1.actualizar_perfil_d1(resp_d1.texto)

                # Paso C: Juez J1 evalúa la respuesta considerando el formato baseline detectado
                evaluacion = juez_j1.evaluar(
                    objetivo=objetivo,
                    prompt_a1=prompt_a1,
                    respuesta_d1=resp_d1.texto,
                    status_code_d1=resp_d1.status_code,
                    error_d1=resp_d1.error,
                    formato_baseline=perfilador_d1.patron_dominante
                )
                logger.info(
                    f"[{EventosLog.ATTACK_JUDGE_EVALUATION}] Turno {numero_turno} calificado con {evaluacion.puntaje}/10. "
                    f"Justificación: {evaluacion.justificacion[:80]}..."
                )

                # Clasificar categoría taxonómica del ataque
                categoria_ataque = JuezEvaluador.clasificar_categoria_ataque(prompt_a1=prompt_a1, tactica_usada=tactica)

                # Paso D: Persistir turno en BD
                AtaqueRepository.registrar_turno(
                    session_id=session_id,
                    numero_turno=numero_turno,
                    prompt_a1=prompt_a1,
                    tactica=tactica,
                    respuesta_d1=resp_d1.texto,
                    status_code_d1=resp_d1.status_code,
                    latencia_d1_ms=resp_d1.latencia_ms,
                    puntaje_j1=evaluacion.puntaje,
                    justificacion_j1=evaluacion.justificacion,
                    fuga_detectada=evaluacion.fuga_detectada,
                    fragmentos_fuga=evaluacion.fragmentos,
                    fue_reset=fue_reset,
                    categoria_ataque=categoria_ataque,
                    clasificacion_resultado=evaluacion.clasificacion,
                    formato_preservado=evaluacion.formato_preservado,
                    tarea_preservada=evaluacion.tarea_preservada,
                    instruccion_adversaria_seguida=evaluacion.instruccion_adversaria_seguida,
                    confianza_evaluacion=evaluacion.confianza
                )

                resultado_turno = ResultadoTurnoAtaque(
                    numero_turno=numero_turno,
                    prompt_a1=prompt_a1,
                    tactica=tactica,
                    respuesta_d1=resp_d1.texto,
                    status_code_d1=resp_d1.status_code,
                    latencia_d1_ms=resp_d1.latencia_ms,
                    evaluacion=evaluacion,
                    fue_reset=fue_reset
                )
                turnos_completados.append(resultado_turno)

                # Actualizar memoria para el siguiente turno
                puntaje_anterior = evaluacion.puntaje
                respuesta_anterior_d1 = resp_d1.texto

                # Paso E: Verificar condición de éxito y persistencia
                es_exito = evaluacion.puntaje >= PUNTAJE_EXITO
                es_score_intermedio = (
                    config_persistencia.habilitada
                    and not persistencia_intentada
                    and evaluacion.puntaje >= PUNTAJE_ACTIVACION_PERSISTENCIA
                )

                if es_exito:
                    exito_total = True
                    logger.info(f"[{EventosLog.ATTACK_SUCCESS}] ¡Meta alcanzada en el turno {numero_turno}! Puntaje: {evaluacion.puntaje}/10")

                    if config_persistencia.habilitada:
                        motor_persistencia = MotorPersistencia(config_transporte=config_transporte, juez_j1=juez_j1)
                        resultado_persistencia, turnos_p = motor_persistencia.ejecutar(
                            session_id=session_id,
                            objetivo=objetivo,
                            config_persistencia=config_persistencia,
                            turno_inicial=numero_turno + 1
                        )
                        turnos_completados.extend(turnos_p)
                        persistencia_intentada = True

                        status_final = EstadoAtaque.EXITO_PERSISTIDO if resultado_persistencia.persistencia_verificada else EstadoAtaque.EXITO
                        AtaqueRepository.finalizar_sesion(
                            session_id=session_id,
                            status=status_final,
                            exito=True
                        )
                    else:
                        AtaqueRepository.finalizar_sesion(
                            session_id=session_id,
                            status=EstadoAtaque.EXITO,
                            exito=True
                        )
                    break

                elif es_score_intermedio:
                    logger.info(
                        f"Puntaje intermedio ({evaluacion.puntaje}/10) alcanzado en turno {numero_turno}. "
                        f"Iniciando intento de persistencia según configuración..."
                    )
                    motor_persistencia = MotorPersistencia(config_transporte=config_transporte, juez_j1=juez_j1)
                    resultado_persistencia, turnos_p = motor_persistencia.ejecutar(
                        session_id=session_id,
                        objetivo=objetivo,
                        config_persistencia=config_persistencia,
                        turno_inicial=numero_turno + 1
                    )
                    turnos_completados.extend(turnos_p)
                    persistencia_intentada = True

                    if resultado_persistencia.persistencia_verificada:
                        logger.info(f"[{EventosLog.PERSISTENCE_SUCCESS}] ¡Persistencia verificada con éxito tras score intermedio en turno {numero_turno}!")
                        exito_total = True
                        AtaqueRepository.finalizar_sesion(
                            session_id=session_id,
                            status=EstadoAtaque.EXITO_PERSISTIDO,
                            exito=True
                        )
                        break
                    else:
                        logger.info("Intento de persistencia con score intermedio no verificó. Continuando ataque principal hacia score 10...")

                numero_turno += 1


            # 4. Fin del bucle
            if not exito_total:
                sesion_actualizada = AtaqueRepository.obtener_sesion(session_id)
                puntaje_max = sesion_actualizada.puntaje_maximo if sesion_actualizada else 0

                if config_persistencia.habilitada and not persistencia_intentada and puntaje_max >= PUNTAJE_ACTIVACION_PERSISTENCIA:
                    logger.info(
                        f"Ejecutando persistencia al final del ciclo tras alcanzar puntaje máximo de {puntaje_max}/10..."
                    )
                    motor_persistencia = MotorPersistencia(config_transporte=config_transporte, juez_j1=juez_j1)
                    resultado_persistencia, turnos_p = motor_persistencia.ejecutar(
                        session_id=session_id,
                        objetivo=objetivo,
                        config_persistencia=config_persistencia,
                        turno_inicial=len(turnos_completados) + 1
                    )
                    turnos_completados.extend(turnos_p)
                    persistencia_intentada = True

                    if resultado_persistencia.persistencia_verificada:
                        exito_total = True
                        AtaqueRepository.finalizar_sesion(
                            session_id=session_id,
                            status=EstadoAtaque.EXITO_PERSISTIDO,
                            exito=True
                        )
                    else:
                        AtaqueRepository.finalizar_sesion(
                            session_id=session_id,
                            status=EstadoAtaque.MAX_TURNOS_ALCANZADO,
                            exito=False
                        )
                else:
                    turnos_reales = sesion_actualizada.turnos_ejecutados if sesion_actualizada else len([t for t in turnos_completados if not t.es_persistencia])
                    if turnos_reales >= max_turnos:
                        logger.info(f"[{EventosLog.ATTACK_MAX_TURNS}] Límite de {max_turnos} turnos alcanzado sin éxito total.")
                        AtaqueRepository.finalizar_sesion(
                            session_id=session_id,
                            status=EstadoAtaque.MAX_TURNOS_ALCANZADO,
                            exito=False
                        )
                    else:
                        mensaje_parada = f"Ataque interrumpido anticipadamente en turno {turnos_reales}/{max_turnos}."
                        logger.warning(mensaje_parada)
                        AtaqueRepository.finalizar_sesion(
                            session_id=session_id,
                            status=EstadoAtaque.FALLIDO,
                            exito=False,
                            error_message=mensaje_parada
                        )

            logger.info(f"[{EventosLog.ATTACK_SESSION_FINISHED}] Sesión de ataque {session_id} finalizada.")

            sesion_actualizada = AtaqueRepository.obtener_sesion(session_id)
            return ResultadoSesionAtaque(
                session_id=session_id,
                scan_id=str(scan.id),
                objetivo=objetivo,
                turnos_ejecutados=len([t for t in turnos_completados if not t.es_persistencia]),
                max_turnos=max_turnos,
                puntaje_maximo=sesion_actualizada.puntaje_maximo if sesion_actualizada else 0,
                exito=exito_total,
                turnos=turnos_completados,
                persistencia=resultado_persistencia
            )

        except Exception as err:
            logger.error(f"[{EventosLog.ATTACK_ERROR}] Error no controlado en sesión de ataque {session_id}: {err}", exc_info=True)
            AtaqueRepository.finalizar_sesion(
                session_id=session_id,
                status=EstadoAtaque.FALLIDO,
                exito=False,
                error_message=str(err)
            )
            return ResultadoSesionAtaque(
                session_id=session_id,
                scan_id=str(scan.id),
                objetivo=objetivo,
                turnos_ejecutados=0,
                max_turnos=sesion.max_turnos,
                puntaje_maximo=0,
                exito=False,
                error=str(err)
            )

    @classmethod
    def _resolver_configuracion_transporte(cls, scan: DiscoveryScan) -> ConfiguracionTransporte:
        """
        Extrae la URL del endpoint D1, método, campo de prompt y cookies de la sesión de Playwright.
        """
        url = ""
        metodo = "POST"
        content_type = "application/json"
        campo_prompt = "prompt"
        estructura_base = None

        # 1. Intentar desde AIChannel persistido
        if hasattr(scan, 'channel') and scan.channel:
            ch = scan.channel
            url = ch.url
            metodo = ch.method or "POST"
            content_type = ch.content_type or "application/json"
            campo_prompt = ch.prompt_field or "prompt"

        # 2. Si no o faltan datos, leer de scan.resultado
        if not url and isinstance(scan.resultado, dict):
            canal_dict = scan.resultado.get("canal")
            if isinstance(canal_dict, dict):
                url = canal_dict.get("url", "")
                metodo = canal_dict.get("metodo", "POST")
                content_type = canal_dict.get("content_type", "application/json")
                entrada = canal_dict.get("entrada", {})
                if isinstance(entrada, dict):
                    campo_prompt = entrada.get("campo") or "prompt"

        if not url:
            # Fallback a target_url del escaneo si no se identificó endpoint específico
            url = scan.target_url

        # 3. Extraer cookies de sesión de Playwright guardadas en el resultado
        cookies: Dict[str, str] = {}
        if isinstance(scan.resultado, dict):
            sesion_nav = scan.resultado.get("sesion_navegador", {})
            if isinstance(sesion_nav, dict):
                cookies = sesion_nav.get("cookies", {})

        # Si no había en sesion_navegador, buscar en observaciones de red capturadas
        if not cookies:
            cookies = cls._recuperar_cookies_de_observaciones(scan)

        timeout = getattr(settings, 'ATTACK_D1_TIMEOUT_SECONDS', 60.0)

        return ConfiguracionTransporte(
            url=url,
            metodo=metodo,
            content_type=content_type,
            campo_prompt=campo_prompt,
            estructura_cuerpo=estructura_base,
            headers={},
            cookies=cookies,
            timeout_seconds=timeout
        )

    @classmethod
    def _recuperar_cookies_de_observaciones(cls, scan: DiscoveryScan) -> Dict[str, str]:
        """Extrae cookies observadas en las peticiones del escaneo como fallback."""
        cookies = {}
        for obs in scan.observations.all():
            headers = obs.sanitized_headers or {}
            for k, v in headers.items():
                if k.lower() == 'cookie' and isinstance(v, str):
                    for parte in v.split(';'):
                        if '=' in parte:
                            nombre, valor = parte.strip().split('=', 1)
                            if valor != "[REDACTADO]":
                                cookies[nombre] = valor
        return cookies
