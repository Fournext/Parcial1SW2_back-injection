"""
Controladores y ViewSets para la API REST de descubrimiento de IA.
"""
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.decorators import action
from backend_genvulnai.models import DiscoveryScan, AttackSession, AttackTurn
from backend_genvulnai.serializers import (
    IniciarEscaneoSerializer,
    DiscoveryScanListSerializer,
    DiscoveryScanDetailSerializer,
    NetworkObservationSerializer,
    IniciarAtaqueSerializer,
    AttackSessionListSerializer,
    AttackSessionDetailSerializer,
    AttackTurnSerializer
)
from backend_genvulnai.repositories.descubrimiento_repository import DescubrimientoRepository
from backend_genvulnai.services.orquestador import OrquestadorDescubrimientoService
from backend_genvulnai.services.orquestador_ataque import OrquestadorAtaqueService



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
        usuario = serializer.validated_data.get('usuario') or None
        contrasena = serializer.validated_data.get('contrasena') or None
        max_profundidad = serializer.validated_data.get('max_profundidad', 10)
        max_pasos = serializer.validated_data.get('max_pasos', 60)

        # 1. Crear el registro en base de datos
        scan = DescubrimientoRepository.crear_escaneo(url=url_objetivo)

        # 2. Iniciar el escaneo asíncrono sin bloquear la respuesta
        OrquestadorDescubrimientoService.iniciar_escaneo_asincrono(
            scan_id=str(scan.id),
            url_objetivo=url_objetivo,
            usuario=usuario,
            contrasena=contrasena,
            max_profundidad=max_profundidad,
            max_pasos=max_pasos,
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


class AttackSessionViewSet(viewsets.ModelViewSet):
    """
    ViewSet para administrar y monitorear sesiones de ataque automatizado (red-teaming).
    Permite iniciar un ataque (POST), listar sesiones (GET) y consultar el progreso y los turnos (GET /id/).
    """
    queryset = AttackSession.objects.all().prefetch_related('turns')

    def get_serializer_class(self):
        if self.action == 'create':
            return IniciarAtaqueSerializer
        elif self.action == 'list':
            return AttackSessionListSerializer
        return AttackSessionDetailSerializer

    def create(self, request, *args, **kwargs):
        """
        POST /api/ataques/
        Inicia una nueva sesión de ataque asíncrona sobre el canal de un escaneo completado.
        """
        serializer = IniciarAtaqueSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        scan_id = str(serializer.validated_data['scan_id'])
        objetivo = serializer.validated_data['objetivo']
        max_turnos = serializer.validated_data.get('max_turnos', 20)
        persistencia = serializer.validated_data.get('persistencia', False)
        vectores_persistencia = serializer.validated_data.get('vectores_persistencia', [])
        turnos_refuerzo = serializer.validated_data.get('turnos_refuerzo', 10)
        turnos_verificacion = serializer.validated_data.get('turnos_verificacion', 5)

        try:
            sesion = OrquestadorAtaqueService.iniciar_ataque_asincrono(
                scan_id=scan_id,
                objetivo=objetivo,
                max_turnos=max_turnos,
                persistencia=persistencia,
                vectores_persistencia=vectores_persistencia,
                turnos_refuerzo=turnos_refuerzo,
                turnos_verificacion=turnos_verificacion,
            )
            data = {
                "id": str(sesion.id),
                "scan_id": str(sesion.scan_id),
                "objetivo": sesion.objetivo,
                "max_turnos": sesion.max_turnos,
                "persistencia_habilitada": sesion.persistencia_habilitada,
                "vectores_persistencia": sesion.vectores_persistencia,
                "turnos_refuerzo": sesion.persistencia_turnos_refuerzo,
                "turnos_verificacion": sesion.persistencia_turnos_verificacion,
                "status": sesion.status,
                "mensaje": "Sesión de ataque iniciada en segundo plano. Consulte el progreso en este mismo endpoint."
            }
            return Response(data, status=status.HTTP_201_CREATED)
        except Exception as exc:
            return Response({"error": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['get'], url_path='turnos')
    def turnos(self, request, pk=None):
        """
        GET /api/ataques/{id}/turnos/
        Retorna la lista de turnos ejecutados en esta sesión.
        """
        sesion = self.get_object()
        turnos = sesion.turns.all()
        serializer = AttackTurnSerializer(turnos, many=True)
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

