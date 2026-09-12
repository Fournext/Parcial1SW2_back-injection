"""
Servicio para el cálculo normalizado del nivel de confianza del canal detectado.
Aplica la ponderación requerida normalizando el valor entre 0.0 y 1.0.
"""
from typing import Optional
from backend_genvulnai.domain.constants import PALABRAS_CLAVE_ENDPOINT
from backend_genvulnai.domain.enums import ModoRespuesta
from backend_genvulnai.domain.schemas import ResultadoCanal, ObservacionRed


class CalculadorConfianzaService:
    """Calcula la probabilidad objetiva de que el canal detectado sea el medio real hacia la IA."""

    @classmethod
    def calcular_confianza(
        cls,
        canal: Optional[ResultadoCanal],
        observacion_asociada: Optional[ObservacionRed] = None,
        hubo_cambio_en_ui: bool = False
    ) -> float:
        """
        Calcula una puntuación de confianza entre 0.00 y 1.00:
        +0.50 marcador encontrado en la petición
        +0.15 respuesta asociada recibida con éxito (200 OK)
        +0.10 endpoint relacionado semánticamente con IA
        +0.10 actualización o renderizado visible en la interfaz
        +0.10 streaming detectado (SSE o chunked)
        +0.05 estructura estándar messages/role/content en el payload
        """
        if not canal:
            return 0.0

        score = 0.0

        # +0.50 Si el marcador se encontró en el cuerpo o trama
        if canal.contiene_marcador:
            score += 0.50

        # +0.15 Si hubo respuesta exitosa asociada
        if observacion_asociada and observacion_asociada.response_status and 200 <= observacion_asociada.response_status < 300:
            score += 0.15
        elif canal.es_websocket:
            score += 0.15

        # +0.10 Si la URL contiene palabras clave de IA
        url_lower = canal.url.lower()
        if any(kw in url_lower for kw in PALABRAS_CLAVE_ENDPOINT):
            score += 0.10

        # +0.10 Si la UI reflejó cambios tras el envío
        if hubo_cambio_en_ui:
            score += 0.10

        # +0.10 Si se detectó Streaming (SSE o WebSocket)
        if canal.modo_respuesta in (ModoRespuesta.SSE, ModoRespuesta.WEBSOCKET, ModoRespuesta.CHUNKED):
            score += 0.10

        # +0.05 Si la estructura del prompt sigue el estándar (messages/content/prompt)
        if canal.campo_prompt and any(p in canal.campo_prompt.lower() for p in ['message', 'prompt', 'content', 'query']):
            score += 0.05

        # Normalizar entre 0.0 y 1.0 con 2 decimales
        return round(min(score, 1.0), 2)

    @classmethod
    def combinar_scores(
        cls, 
        score_heuristico: float, 
        score_ia: float,
        peso_heuristica: float = 0.65,
        peso_ia: float = 0.35
    ) -> float:
        """
        Combina ponderadamente la confianza heurística/determinista con la confianza semántica del LLM.

        Fórmula:
            score_final = (score_heuristico * peso_heuristica) + (score_ia * peso_ia)

        Args:
            score_heuristico: Confianza calculada por reglas técnicas (0.0 a 1.0).
            score_ia: Confianza estimada por Ollama (0.0 a 1.0).
            peso_heuristica: Ponderación de la heurística (por defecto 0.65).
            peso_ia: Ponderación del análisis de IA (por defecto 0.35).

        Returns:
            Score combinado redondeado a 2 decimales y acotado entre 0.0 y 1.0.
        """
        score_combinado = (score_heuristico * peso_heuristica) + (score_ia * peso_ia)
        return round(max(0.0, min(1.0, score_combinado)), 2)

