"""
Pruebas para la gestión dinámica de URLs autorizadas (AllowedTargetURL) y su integración con el validador.
"""
import pytest
from rest_framework import status
from backend_genvulnai.models import AllowedTargetURL
from backend_genvulnai.services.validador_url import ValidadorURLService
from backend_genvulnai.exceptions import URLNoPermitidaError


@pytest.mark.django_db
def test_crear_url_autorizada_api(api_client):
    """Verifica la creación de un nuevo objetivo autorizado vía POST /api/urls-autorizadas/."""
    payload = {
        "url": "http://192.168.100.50:9000",
        "descripcion": "Servidor IA interno de pruebas",
        "activa": True
    }
    response = api_client.post('/api/urls-autorizadas/', payload, format='json')
    assert response.status_code == status.HTTP_201_CREATED
    assert response.data['url'] == "http://192.168.100.50:9000"
    assert response.data['activa'] is True
    assert 'id' in response.data

    # Validar que ahora ValidadorURLService autorice esta URL
    valido, url_norm = ValidadorURLService.validar_url("http://192.168.100.50:9000/api/chat")
    assert valido is True
    assert url_norm == "http://192.168.100.50:9000/api/chat"


@pytest.mark.django_db
def test_crear_url_invalida_rechazada(api_client):
    """Verifica que esquemas no permitidos sean rechazados por el serializer."""
    payload = {
        "url": "file:///etc/passwd",
        "descripcion": "Ruta inválida"
    }
    response = api_client.post('/api/urls-autorizadas/', payload, format='json')
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert 'url' in response.data


@pytest.mark.django_db
def test_listar_urls_autorizadas(api_client):
    """Verifica el listado de URLs autorizadas y el endpoint de efectivas."""
    AllowedTargetURL.objects.create(
        url="http://test-target-ai.local:8080",
        descripcion="Test Target"
    )

    response = api_client.get('/api/urls-autorizadas/')
    assert response.status_code == status.HTTP_200_OK
    assert len(response.data) >= 1

    resp_efectivas = api_client.get('/api/urls-autorizadas/efectivas/')
    assert resp_efectivas.status_code == status.HTTP_200_OK
    assert "hosts_y_urls_permitidos" in resp_efectivas.data
    assert "http://test-target-ai.local:8080" in resp_efectivas.data["hosts_y_urls_permitidos"]


@pytest.mark.django_db
def test_desactivar_o_eliminar_url_autorizada(api_client):
    """Verifica que una URL desactivada o eliminada deje de ser autorizada."""
    obj = AllowedTargetURL.objects.create(
        url="http://10.20.30.40:5000",
        descripcion="Temporal",
        activa=True
    )

    # Autorizada inicialmente
    valido, _ = ValidadorURLService.validar_url("http://10.20.30.40:5000/chat")
    assert valido is True

    # Desactivar mediante PATCH
    patch_resp = api_client.patch(f'/api/urls-autorizadas/{obj.id}/', {'activa': False}, format='json')
    assert patch_resp.status_code == status.HTTP_200_OK
    assert patch_resp.data['activa'] is False

    # Ahora debe fallar la validación si no está en .env
    with pytest.raises(URLNoPermitidaError):
        ValidadorURLService.validar_url("http://10.20.30.40:5000/chat")

    # Eliminar completamente
    del_resp = api_client.delete(f'/api/urls-autorizadas/{obj.id}/')
    assert del_resp.status_code == status.HTTP_204_NO_CONTENT
    assert not AllowedTargetURL.objects.filter(id=obj.id).exists()
