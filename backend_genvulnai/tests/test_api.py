"""
Pruebas para los endpoints de la API REST /api/descubrimientos/.
"""
import pytest
from unittest.mock import patch
from rest_framework import status
from backend_genvulnai.models import DiscoveryScan
from backend_genvulnai.domain.enums import EstadoEscaneo


@pytest.mark.django_db
def test_crear_escaneo_exitoso(api_client):
    with patch('backend_genvulnai.services.orquestador.OrquestadorDescubrimientoService.iniciar_escaneo_asincrono') as mock_async:
        response = api_client.post(
            '/api/descubrimientos/',
            {
                'url': 'http://localhost:3000',
                'max_profundidad': 8,
                'max_pasos': 75
            },
            format='json'
        )

        assert response.status_code == status.HTTP_201_CREATED
        assert 'id' in response.data
        assert response.data['target_url'] == 'http://localhost:3000'
        assert response.data['status'] == EstadoEscaneo.PENDIENTE
        
        # Verificar que los parámetros se hayan pasado correctamente al orquestador
        mock_async.assert_called_once()
        _, kwargs = mock_async.call_args
        assert kwargs['max_profundidad'] == 8
        assert kwargs['max_pasos'] == 75


@pytest.mark.django_db
def test_crear_escaneo_url_no_permitida(api_client):
    response = api_client.post(
        '/api/descubrimientos/',
        {'url': 'file:///etc/hosts'},
        format='json'
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert 'url' in response.data


@pytest.mark.django_db
def test_listar_escaneos(api_client):
    DiscoveryScan.objects.create(target_url='http://localhost:8080')
    response = api_client.get('/api/descubrimientos/')

    assert response.status_code == status.HTTP_200_OK
    assert len(response.data) >= 1


@pytest.mark.django_db
def test_detalle_escaneo_no_encontrado(api_client):
    import uuid
    id_aleatorio = uuid.uuid4()
    response = api_client.get(f'/api/descubrimientos/{id_aleatorio}/')

    assert response.status_code == status.HTTP_404_NOT_FOUND
