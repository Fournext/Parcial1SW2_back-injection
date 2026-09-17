"""
Enrutamiento de la aplicación backend_genvulnai.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from backend_genvulnai.views import DescubrimientoViewSet, AttackSessionViewSet, OllamaHealthView

router = DefaultRouter()
router.register(r'descubrimientos', DescubrimientoViewSet, basename='descubrimiento')
router.register(r'ataques', AttackSessionViewSet, basename='ataque')

urlpatterns = [
    path('sistema/ollama/', OllamaHealthView.as_view(), name='ollama-health'),
    path('', include(router.urls)),
]

