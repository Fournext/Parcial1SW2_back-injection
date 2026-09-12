"""
Pruebas unitarias para la combinación ponderada de puntajes de confianza entre heurística y Ollama.
"""
import pytest
from backend_genvulnai.domain.constants import PESO_HEURISTICA, PESO_IA
from backend_genvulnai.services.calculador_confianza import CalculadorConfianzaService


def test_combinacion_scores_ponderacion_estandar():
    """
    Verifica la fórmula: score_final = score_heuristico * 0.65 + score_ia * 0.35.
    Ejemplo:
      heuristica = 0.60
      ia = 0.90
      0.60 * 0.65 + 0.90 * 0.35 = 0.39 + 0.315 = 0.705 -> redondeado a 0.71 o 0.70
    """
    score = CalculadorConfianzaService.combinar_scores(
        score_heuristico=0.60,
        score_ia=0.90,
        peso_heuristica=PESO_HEURISTICA,
        peso_ia=PESO_IA
    )
    # 0.39 + 0.315 = 0.705
    assert score == round(0.60 * 0.65 + 0.90 * 0.35, 2)


def test_combinacion_scores_ambos_maximos():
    """Verifica que si ambos son 1.0 el resultado es 1.0."""
    score = CalculadorConfianzaService.combinar_scores(1.0, 1.0)
    assert score == 1.0


def test_combinacion_scores_ambos_ceros():
    """Verifica que si ambos son 0.0 el resultado es 0.0."""
    score = CalculadorConfianzaService.combinar_scores(0.0, 0.0)
    assert score == 0.0


def test_combinacion_scores_acotamiento_limites():
    """Verifica que el puntaje nunca supere 1.0 ni sea inferior a 0.0."""
    score_alto = CalculadorConfianzaService.combinar_scores(1.5, 1.2)
    assert score_alto == 1.0

    score_bajo = CalculadorConfianzaService.combinar_scores(-0.5, -0.2)
    assert score_bajo == 0.0
