"""
Controladores y ViewSets para la API REST de descubrimiento de IA.
"""
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.decorators import action
from backend_genvulnai.models import DiscoveryScan
from backend_genvulnai.serializers import (
    IniciarEscaneoSerializer,
    DiscoveryScanListSerializer,
    DiscoveryScanDetailSerializer,
    NetworkObservationSerializer
)
from backend_genvulnai.repositories.descubrimiento_repository import DescubrimientoRepository
from backend_genvulnai.services.orquestador import OrquestadorDescubrimientoService


class DescubrimientoViewSet(viewsets.ModelViewSet):
    """
    ViewSet principal para administrar escaneos de aplicaciones con IA.
    Permite crear análisis, consultar su progreso y obtener detalles de red y canales.
    """
    queryset = DiscoveryScan.objects.all().select_related('ai_channel').prefetch_related('observations')

    def get_serializer_class(self):
        if self.action == 'create':
            return IniciarEscaneoSerializer
        elif self.action == 'list':
            return DiscoveryScanListSerializer
        return DiscoveryScanDetailSerializer

    def create(self, request, *args, **kwargs):
        """
        POST /api/descubrimientos/
        Crea un nuevo escaneo para la URL objetivo y dispara el análisis en segundo plano.
        """
        serializer = IniciarEscaneoSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        url_objetivo = serializer.validated_data['url']

        # 1. Crear el registro en base de datos
        scan = DescubrimientoRepository.crear_escaneo(url=url_objetivo)

        # 2. Iniciar el escaneo asíncrono sin bloquear la respuesta
        OrquestadorDescubrimientoService.iniciar_escaneo_asincrono(
            scan_id=str(scan.id),
            url_objetivo=url_objetivo
        )

        respuesta_data = {
            "id": str(scan.id),
            "target_url": scan.target_url,
            "status": scan.status,
            "mensaje": "Escaneo iniciado exitosamente. Consulte el estado en este mismo endpoint."
        }
        return Response(respuesta_data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=['get'], url_path='observaciones')
    def observaciones(self, request, pk=None):
        """
        GET /api/descubrimientos/{id}/observaciones/
        Lista todas las peticiones de red capturadas y sanitizadas para este escaneo.
        """
        scan = self.get_object()
        observaciones = scan.observations.all()
        serializer = NetworkObservationSerializer(observaciones, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


from rest_framework.views import APIView
from backend_genvulnai.services.analizador_ia import AnalizadorIA


class OllamaHealthView(APIView):
    """
    Endpoint de diagnóstico para consultar el estado de salud y disponibilidad de Ollama local.
    GET /api/sistema/ollama/
    """
    def get(self, request, *args, **kwargs):
        analizador = AnalizadorIA()
        estado = analizador.obtener_estado()
        
        datos = {
            "disponible": estado.disponible,
            "modelo_configurado": estado.modelo_configurado,
            "modelo_presente": estado.modelo_presente,
            "modelos_disponibles": estado.modelos_disponibles,
            "error": estado.error
        }
        status_code = status.HTTP_200_OK if estado.disponible else status.HTTP_503_SERVICE_UNAVAILABLE
        return Response(datos, status=status_code)

