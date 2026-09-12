"""
Servicio de análisis semántico mediante IA (Ollama) para resolver ambigüedades en interfaces y tráfico de red.
"""
import logging
from typing import Any, Dict, List, Optional

from backend_genvulnai.domain.constants import EventosLog
from backend_genvulnai.domain.schemas import (
    AnalisisCanalIA,
    AnalisisInterfazIA,
    EstadoOllama,
)
from backend_genvulnai.prompts.evaluar_respuesta import (
    PROMPT_SISTEMA_RESPUESTA,
    construir_prompt_evaluacion_respuesta,
)
from backend_genvulnai.prompts.seleccionar_canal import (
    PROMPT_SISTEMA_CANAL,
    construir_prompt_canal,
)
from backend_genvulnai.prompts.seleccionar_interfaz import (
    PROMPT_SISTEMA_INTERFAZ,
    construir_prompt_interfaz,
)
from backend_genvulnai.services.cliente_ollama import ClienteOllama

logger = logging.getLogger('backend_genvulnai')


class AnalizadorIA:
    """
    Capa de análisis semántico complementaria respaldada por Ollama.
    Solo se invoca cuando los métodos deterministas/heurísticos arrojan resultados ambiguos.
    """

    def __init__(self, cliente_ollama: Optional[ClienteOllama] = None):
        self.cliente = cliente_ollama or ClienteOllama()

    def esta_disponible(self) -> bool:
        """
        Verifica rápidamente si el servicio Ollama está configurado y respondiendo.

        Returns:
            True si Ollama está en línea y el modelo configurado está disponible.
        """
        try:
            estado = self.cliente.consultar_estado()
            return estado.disponible and estado.modelo_presente
        except Exception as exc:
            logger.warning(f"Error al verificar disponibilidad de Ollama: {str(exc)}")
            return False

    def obtener_estado(self) -> EstadoOllama:
        """Obtiene el diagnóstico completo del estado de Ollama."""
        return self.cliente.consultar_estado()

    def seleccionar_interfaz(
        self, 
        candidatos: List[Dict[str, Any]]
    ) -> Optional[AnalisisInterfazIA]:
        """
        Analiza una lista de elementos de interfaz candidatos para determinar semánticamente cuál es el campo de IA.

        Args:
            candidatos: Lista de diccionarios de elementos candidatos (con puntaje y atributos).

        Returns:
            AnalisisInterfazIA con el índice y justificación, o None en caso de fallo.
        """
        if not candidatos:
            return None

        # Preparar representación compacta y segura para el LLM
        candidatos_formateados = []
        for idx, c in enumerate(candidatos):
            candidatos_formateados.append({
                "indice": idx,
                "tag": c.get("tag", ""),
                "id": c.get("id", ""),
                "name": c.get("name", ""),
                "placeholder": c.get("placeholder", ""),
                "aria_label": c.get("aria_label", ""),
                "role": c.get("role", ""),
                "classes": c.get("classes", ""),
                "tipo_interfaz": c.get("tipo_interfaz", ""),
                "score_heuristico": c.get("confianza", 0.0)
            })

        prompt_usuario = construir_prompt_interfaz(candidatos_formateados)
        respuesta_json = self.cliente.chat(PROMPT_SISTEMA_INTERFAZ, prompt_usuario)

        if not respuesta_json:
            return None

        try:
            idx_seleccionado = respuesta_json.get("indice_seleccionado")
            # Validar que el índice sea válido si no es null
            if idx_seleccionado is not None:
                idx_int = int(idx_seleccionado)
                if not (0 <= idx_int < len(candidatos)):
                    idx_seleccionado = None
                else:
                    idx_seleccionado = idx_int

            confianza = float(respuesta_json.get("confianza", 0.0))
            # Acotar confianza entre 0.0 y 1.0
            confianza = max(0.0, min(1.0, confianza))
            
            justificacion = str(respuesta_json.get("justificacion", "Sin justificación provista"))
            evidencia_insuficiente = bool(respuesta_json.get("evidencia_insuficiente", False))

            return AnalisisInterfazIA(
                indice_seleccionado=idx_seleccionado,
                confianza_ia=confianza,
                justificacion=justificacion,
                evidencia_insuficiente=evidencia_insuficiente
            )
        except (ValueError, TypeError) as exc:
            logger.warning(
                f"[{EventosLog.OLLAMA_JSON_PARSE_ERROR}] Error interpretando estructura del JSON de interfaz: {str(exc)}"
            )
            return None

    def seleccionar_canal(
        self, 
        observaciones: List[Dict[str, Any]], 
        marcador: str
    ) -> Optional[AnalisisCanalIA]:
        """
        Analiza observaciones de red candidatas para resolver cuál representa el canal principal de IA.

        Args:
            observaciones: Lista de observaciones de red sanitizadas.
            marcador: Marcador inyectado en la prueba.

        Returns:
            AnalisisCanalIA con los detalles técnicos identificados o None.
        """
        if not observaciones:
            return None

        # Preparar versión reducida y estrictamente sanitizada
        observaciones_formateadas = []
        for idx, obs in enumerate(observaciones):
            cuerpo_muestra = obs.get("body_preview", "") or obs.get("request_body", "") or ""
            if len(cuerpo_muestra) > 500:
                cuerpo_muestra = cuerpo_muestra[:500] + "..."

            observaciones_formateadas.append({
                "indice": idx,
                "protocolo": obs.get("protocolo", "HTTP"),
                "metodo": obs.get("method", obs.get("metodo", "POST")),
                "url": obs.get("url", ""),
                "status_code": obs.get("status_code", 0),
                "content_type": obs.get("content_type", ""),
                "contiene_marcador": obs.get("contiene_marcador", False),
                "cuerpo_muestra": cuerpo_muestra
            })

        prompt_usuario = construir_prompt_canal(observaciones_formateadas, marcador)
        respuesta_json = self.cliente.chat(PROMPT_SISTEMA_CANAL, prompt_usuario)

        if not respuesta_json:
            return None

        try:
            idx_seleccionado = respuesta_json.get("indice_seleccionado")
            if idx_seleccionado is not None:
                idx_int = int(idx_seleccionado)
                if not (0 <= idx_int < len(observaciones)):
                    idx_seleccionado = None
                else:
                    idx_seleccionado = idx_int

            confianza = float(respuesta_json.get("confianza", 0.0))
            confianza = max(0.0, min(1.0, confianza))

            campo_prompt = respuesta_json.get("campo_prompt")
            if campo_prompt and not isinstance(campo_prompt, str):
                campo_prompt = str(campo_prompt)

            modo_entrada = respuesta_json.get("modo_entrada")
            modo_respuesta = respuesta_json.get("modo_respuesta")
            justificacion = str(respuesta_json.get("justificacion", "Sin justificación provista"))
            evidencia_insuficiente = bool(respuesta_json.get("evidencia_insuficiente", False))

            return AnalisisCanalIA(
                indice_seleccionado=idx_seleccionado,
                confianza_ia=confianza,
                campo_prompt=campo_prompt,
                modo_entrada=modo_entrada,
                modo_respuesta=modo_respuesta,
                justificacion=justificacion,
                evidencia_insuficiente=evidencia_insuficiente
            )
        except (ValueError, TypeError) as exc:
            logger.warning(
                f"[{EventosLog.OLLAMA_JSON_PARSE_ERROR}] Error interpretando estructura del JSON de canal: {str(exc)}"
            )
            return None

    def evaluar_modo_respuesta(self, respuesta_meta: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Evalúa semánticamente el modo de respuesta de un endpoint de IA.

        Args:
            respuesta_meta: Metadatos de la respuesta HTTP.

        Returns:
            Diccionario con modo_respuesta y confianza, o None.
        """
        prompt_usuario = construir_prompt_evaluacion_respuesta(respuesta_meta)
        return self.cliente.chat(PROMPT_SISTEMA_RESPUESTA, prompt_usuario)
