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
def test_crear_escaneo_con_software_id(api_client):
    with patch('backend_genvulnai.services.orquestador.OrquestadorDescubrimientoService.iniciar_escaneo_asincrono'):
        response = api_client.post(
            '/api/descubrimientos/',
            {
                'url': 'http://localhost:3000',
                'software_id': 42
            },
            format='json'
        )

        assert response.status_code == status.HTTP_201_CREATED
        assert response.data['software_id'] == 42
        
        scan = DiscoveryScan.objects.get(id=response.data['id'])
        assert scan.software_id == 42


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
def test_filtrar_escaneos_por_software_id(api_client):
    DiscoveryScan.objects.create(target_url='http://localhost:8080', software_id=10)
    DiscoveryScan.objects.create(target_url='http://localhost:8081', software_id=20)

    response = api_client.get('/api/descubrimientos/?software_id=10')
    assert response.status_code == status.HTTP_200_OK
    assert len(response.data) == 1
    assert response.data[0]['software_id'] == 10


@pytest.mark.django_db
def test_obtener_informe_consolidado(api_client):
    scan = DiscoveryScan.objects.create(
        target_url='http://localhost:8080',
        software_id=99,
        status=EstadoEscaneo.COMPLETADO
    )

    response = api_client.get('/api/descubrimientos/informe/?software_id=99')
    assert response.status_code == status.HTTP_200_OK
    assert response.data['software_id'] == 99
    assert response.data['resumen']['total_escaneos'] == 1
    assert response.data['ultimo_escaneo']['id'] == str(scan.id)
    assert 'fecha_generacion' in response.data
    assert 'canales_descubiertos' in response.data
    assert 'hallazgos_vulnerabilidad' in response.data


@pytest.mark.django_db
def test_detalle_escaneo_no_encontrado(api_client):
    import uuid
    id_aleatorio = uuid.uuid4()
    response = api_client.get(f'/api/descubrimientos/{id_aleatorio}/')
    assert response.status_code == status.HTTP_404_NOT_FOUND
