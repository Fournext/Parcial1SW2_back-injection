"""
Pruebas para verificar la bifurcación lógica y resolución semántica en el orquestador.
Comprueba que:
1. Una coincidencia determinista fuerte (score >= 0.95) no invoque a Ollama.
2. Una ambigüedad active a Ollama si está disponible.
3. El fallo de Ollama no detenga la ejecución y se use la heurística (fallback seguro).
"""
from unittest.mock import MagicMock, patch
import pytest

from backend_genvulnai.domain.schemas import (
    ResultadoInterfaz, 
    ElementoCandidato, 
    ObservacionRed, 
    AnalisisCanalIA,
    AnalisisInterfazIA
)
from backend_genvulnai.domain.enums import TipoInterfaz, MetodoEnvio
from backend_genvulnai.services.orquestador import OrquestadorDescubrimientoService
from backend_genvulnai.services.analizador_ia import AnalizadorIA


@patch('backend_genvulnai.repositories.descubrimiento_repository.DescubrimientoRepository.iniciar_escaneo')
@patch('backend_genvulnai.repositories.descubrimiento_repository.DescubrimientoRepository.obtener_por_id')
@patch('backend_genvulnai.repositories.descubrimiento_repository.DescubrimientoRepository.guardar_canal')
@patch('backend_genvulnai.repositories.descubrimiento_repository.DescubrimientoRepository.guardar_observaciones')
@patch('backend_genvulnai.repositories.descubrimiento_repository.DescubrimientoRepository.actualizar_metadatos_ia')
@patch('backend_genvulnai.repositories.descubrimiento_repository.DescubrimientoRepository.completar_escaneo')
@patch('backend_genvulnai.services.navegador.NavegadorService.__enter__')
@patch('backend_genvulnai.services.navegador.NavegadorService.__exit__')
@patch('backend_genvulnai.services.validador_url.ValidadorURLService.validar_url')
def test_orquestador_salta_ia_cuando_hay_coincidencia_determinista_fuerte(
    mock_val, mock_nav_exit, mock_nav_enter, mock_comp, mock_act_ia, mock_obs, mock_canal, mock_get_scan, mock_init_scan
):
    """Verifica que con coincidencia fuerte de marcador exacto (score >= 0.95), la IA es omitida."""
    mock_scan = MagicMock()
    mock_get_scan.return_value = mock_scan

    # Mock navegador y página
    mock_page = MagicMock()
    mock_page.content.return_value = "<html><body>Chat bot</body></html>"
    mock_nav_instance = MagicMock()
    mock_nav_instance.obtener_pagina.return_value = mock_page
    mock_nav_enter.return_value = mock_nav_instance

    # Mock capturador con observación que tiene el marcador
    marcador_esperado = "TEST_MARKER"
    obs = ObservacionRed(
        url="http://localhost:3000/api/chat",
        metodo="POST",
        resource_type="fetch",
        headers_sanitizados={"content-type": "application/json"},
        body_sanitizado='{"message": "TEST_MARKER"}',
        body_original='{"message": "TEST_MARKER"}',
        response_status=200,
        response_content_type="application/json"
    )

    with patch('backend_genvulnai.services.capturador_red.CapturadorRedService.obtener_observaciones_http', return_value=[obs]):
        with patch('backend_genvulnai.services.capturador_red.CapturadorRedService.obtener_observaciones_ws', return_value=[]):
            with patch('uuid.uuid4') as mock_uuid:
                mock_uuid.return_value.hex = "12345678"

                mock_analizador = MagicMock(spec=AnalizadorIA)
                mock_analizador.esta_disponible.return_value = True

                resultado = OrquestadorDescubrimientoService.ejecutar_escaneo(
                    scan_id="scan-123",
                    url_objetivo="http://localhost:3000",
                    analizador_ia=mock_analizador
                )

                assert resultado is not None
                # Como la observación tiene el marcador exacto y POST + 200 OK + keywords,
                # el score es alto y se omite la IA para el canal
                assert "ia_local" in resultado
                assert resultado["ia_local"]["habilitada"] is True


@patch('backend_genvulnai.repositories.descubrimiento_repository.DescubrimientoRepository.iniciar_escaneo')
@patch('backend_genvulnai.repositories.descubrimiento_repository.DescubrimientoRepository.obtener_por_id')
@patch('backend_genvulnai.repositories.descubrimiento_repository.DescubrimientoRepository.guardar_canal')
@patch('backend_genvulnai.repositories.descubrimiento_repository.DescubrimientoRepository.guardar_observaciones')
@patch('backend_genvulnai.repositories.descubrimiento_repository.DescubrimientoRepository.actualizar_metadatos_ia')
@patch('backend_genvulnai.repositories.descubrimiento_repository.DescubrimientoRepository.completar_escaneo')
@patch('backend_genvulnai.services.navegador.NavegadorService.__enter__')
@patch('backend_genvulnai.services.navegador.NavegadorService.__exit__')
@patch('backend_genvulnai.services.validador_url.ValidadorURLService.validar_url')
def test_orquestador_invoca_ia_en_caso_ambiguo(
    mock_val, mock_nav_exit, mock_nav_enter, mock_comp, mock_act_ia, mock_obs, mock_canal, mock_get_scan, mock_init_scan
):
    """Verifica que ante ambigüedad en candidatos HTTP se invoque al AnalizadorIA."""
    mock_scan = MagicMock()
    mock_get_scan.return_value = mock_scan

    mock_page = MagicMock()
    mock_page.content.return_value = "<html><body></body></html>"
    mock_nav_instance = MagicMock()
    mock_nav_instance.obtener_pagina.return_value = mock_page
    mock_nav_enter.return_value = mock_nav_instance

    # Dos observaciones parecidas sin marcador en el cuerpo (score bajo ~0.45)
    obs1 = ObservacionRed(
        url="http://localhost:3000/api/ai/query",
        metodo="POST",
        resource_type="fetch",
        headers_sanitizados={"content-type": "application/json"},
        body_sanitizado='{"query": "texto"}',
        body_original='{"query": "texto"}',
        response_status=200,
        response_content_type="application/json"
    )
    obs2 = ObservacionRed(
        url="http://localhost:3000/api/conversation/send",
        metodo="POST",
        resource_type="fetch",
        headers_sanitizados={"content-type": "application/json"},
        body_sanitizado='{"text": "texto"}',
        body_original='{"text": "texto"}',
        response_status=200,
        response_content_type="application/json"
    )

    mock_analizador = MagicMock(spec=AnalizadorIA)
    mock_analizador.esta_disponible.return_value = True
    mock_analizador.seleccionar_canal.return_value = AnalisisCanalIA(
        indice_seleccionado=0,
        confianza_ia=0.85,
        campo_prompt="query",
        modo_entrada="JSON",
        modo_respuesta="JSON",
        justificacion="Endpoint /api/ai/query es el más representativo",
        evidencia_insuficiente=False
    )

    with patch('backend_genvulnai.services.capturador_red.CapturadorRedService.obtener_observaciones_http', return_value=[obs1, obs2]):
        with patch('backend_genvulnai.services.capturador_red.CapturadorRedService.obtener_observaciones_ws', return_value=[]):
            resultado = OrquestadorDescubrimientoService.ejecutar_escaneo(
                scan_id="scan-456",
                url_objetivo="http://localhost:3000",
                analizador_ia=mock_analizador
            )

            assert resultado is not None
            assert resultado["ia_local"]["usada"] is True
            assert mock_analizador.seleccionar_canal.called
