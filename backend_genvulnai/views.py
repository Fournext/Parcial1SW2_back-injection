"""
Controladores y ViewSets para la API REST de descubrimiento de IA.
"""
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.decorators import action
from backend_genvulnai.models import (
    DiscoveryScan,
    AttackSession,
    AttackTurn,
    AllowedTargetURL
)
from backend_genvulnai.serializers import (
    IniciarEscaneoSerializer,
    AIChannelSerializer,
    DiscoveryScanListSerializer,
    DiscoveryScanDetailSerializer,
    NetworkObservationSerializer,
    IniciarAtaqueSerializer,
    AttackSessionListSerializer,
    AttackSessionDetailSerializer,
    AttackTurnSerializer,
    AllowedTargetURLSerializer
)
from backend_genvulnai.repositories.descubrimiento_repository import DescubrimientoRepository
from backend_genvulnai.services.orquestador import OrquestadorDescubrimientoService
from backend_genvulnai.services.orquestador_ataque import OrquestadorAtaqueService



class DescubrimientoViewSet(viewsets.ModelViewSet):
    """
    ViewSet principal para administrar escaneos de aplicaciones con IA.
    Permite crear análisis, consultar su progreso y obtener detalles de red y canales.
    """
    def get_queryset(self):
        """Permite filtrar escaneos por software_id vía parámetro de consulta (?software_id=X)."""
        qs = DiscoveryScan.objects.all().select_related('ai_channel').prefetch_related('observations')
        software_id = self.request.query_params.get('software_id')
        if software_id is not None:
            try:
                qs = qs.filter(software_id=int(software_id))
            except ValueError:
                pass
        return qs

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
        software_id = serializer.validated_data.get('software_id')
        usuario = serializer.validated_data.get('usuario') or None
        contrasena = serializer.validated_data.get('contrasena') or None
        max_profundidad = serializer.validated_data.get('max_profundidad', 10)
        max_pasos = serializer.validated_data.get('max_pasos', 60)

        # 1. Crear el registro en base de datos
        scan = DescubrimientoRepository.crear_escaneo(url=url_objetivo, software_id=software_id)

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
            "software_id": scan.software_id,
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

    @action(detail=False, methods=['get'], url_path='informe')
    def informe(self, request):
        """
        GET /api/descubrimientos/informe/?software_id={id}
        Genera un informe consolidado del descubrimiento y seguridad para un software_id determinado.
        """
        import logging
        import uuid
        from django.conf import settings
        from django.utils import timezone
        from backend_genvulnai.domain.enums import EstadoEscaneo
        from backend_genvulnai.models import AttackSession, AttackTurn

        software_id = request.query_params.get('software_id')
        queryset = DiscoveryScan.objects.all().select_related('ai_channel').prefetch_related('observations', 'attack_sessions__turns')

        if software_id is not None:
            try:
                software_id_int = int(software_id)
                queryset = queryset.filter(software_id=software_id_int)
            except ValueError:
                return Response(
                    {"error": "El parámetro software_id debe ser un número entero válido."},
                    status=status.HTTP_400_BAD_REQUEST
                )

        escaneos = list(queryset.order_by('-created_at'))

        # Canales descubiertos
        canales_descubiertos = []
        for s in escaneos:
            if hasattr(s, 'ai_channel') and s.ai_channel:
                canales_descubiertos.append({
                    "scan_id": str(s.id),
                    "channel_type": s.ai_channel.channel_type,
                    "protocol": s.ai_channel.protocol,
                    "url": s.ai_channel.url,
                    "method": s.ai_channel.method,
                    "confidence": s.ai_channel.confidence
                })

        # Sesiones de ataque asociadas a estos escaneos
        scan_ids = [s.id for s in escaneos]
        sesiones_ataque = list(AttackSession.objects.filter(scan_id__in=scan_ids).prefetch_related('turns'))

        hallazgos_vulnerabilidad = []
        puntaje_vulnerabilidad_maximo = 0
        evaluaciones_exitosas = 0

        for sesion in sesiones_ataque:
            if sesion.exito:
                evaluaciones_exitosas += 1
            if sesion.puntaje_maximo > puntaje_vulnerabilidad_maximo:
                puntaje_vulnerabilidad_maximo = sesion.puntaje_maximo

            for turno in sesion.turns.all():
                if turno.fuga_detectada or (turno.puntaje_j1 and turno.puntaje_j1 >= 7):
                    hallazgos_vulnerabilidad.append({
                        "session_id": str(sesion.id),
                        "numero_turno": turno.numero_turno,
                        "tactica_usada": turno.tactica_usada,
                        "puntaje_juez": turno.puntaje_j1,
                        "justificacion": turno.justificacion_j1,
                        "fragmentos_fuga": turno.fragmentos_fuga
                    })

        # Buscar el último escaneo completado
        ultimo_escaneo_completado = next((s for s in escaneos if s.status == EstadoEscaneo.COMPLETADO), None)
        canal_obj = getattr(ultimo_escaneo_completado, 'ai_channel', None) if ultimo_escaneo_completado else None

        canal_data = None
        if canal_obj:
            canal_data = AIChannelSerializer(canal_obj).data

        # Observaciones relevantes sanitizadas
        observaciones_relevantes = []
        if ultimo_escaneo_completado:
            obs_qs = ultimo_escaneo_completado.observations.filter(contains_marker=True)[:20]
            if not obs_qs.exists():
                obs_qs = ultimo_escaneo_completado.observations.all()[:20]
            observaciones_relevantes = NetworkObservationSerializer(obs_qs, many=True).data

        escaneos_serializer = DiscoveryScanListSerializer(escaneos, many=True)
        sesiones_ataque_serializer = AttackSessionDetailSerializer(sesiones_ataque, many=True)

        informe_data = {
            "software_id": int(software_id) if software_id is not None else None,
            "fecha_generacion": timezone.now().isoformat(),
            "resumen": {
                "total_escaneos": len(escaneos),
                "escaneos_completados": sum(1 for s in escaneos if s.status == EstadoEscaneo.COMPLETADO),
                "escaneos_fallidos": sum(1 for s in escaneos if s.status == EstadoEscaneo.FALLIDO),
                "canales_ia_identificados": len(canales_descubiertos),
                "total_evaluaciones_ataque": len(sesiones_ataque),
                "evaluaciones_exitosas_vulnerables": evaluaciones_exitosas,
                "puntaje_vulnerabilidad_maximo": puntaje_vulnerabilidad_maximo
            },
            "ultimo_escaneo": DiscoveryScanDetailSerializer(escaneos[0]).data if escaneos else None,
            "canales_descubiertos": canales_descubiertos,
            "hallazgos_vulnerabilidad": hallazgos_vulnerabilidad,
            "sesiones_ataque": sesiones_ataque_serializer.data,
            "canal_ia_detectado": canal_data,
            "observaciones_relevantes": observaciones_relevantes,
            "escaneos": escaneos_serializer.data
        }

        return Response(informe_data, status=status.HTTP_200_OK)


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


class AllowedTargetURLViewSet(viewsets.ModelViewSet):
    """
    ViewSet para administrar dinámicamente las URLs y hosts objetivos autorizados.
    Permite crear (POST), listar (GET), actualizar (PUT/PATCH) y eliminar (DELETE) destinos.
    """
    queryset = AllowedTargetURL.objects.all()
    serializer_class = AllowedTargetURLSerializer

    @action(detail=False, methods=['get'], url_path='efectivas')
    def efectivas(self, request):
        """
        GET /api/urls-autorizadas/efectivas/
        Retorna la lista consolidada de todas las URLs y hosts permitidos actualmente por el sistema,
        combinando variables de entorno (.env) y los registros activos en la base de datos.
        """
        from backend_genvulnai.services.validador_url import ValidadorURLService
        hosts_permitidos = ValidadorURLService.obtener_hosts_permitidos()
        db_urls = list(AllowedTargetURL.objects.filter(activa=True).values('id', 'url', 'descripcion', 'created_at'))

        return Response({
            "total_efectivos": len(hosts_permitidos),
            "hosts_y_urls_permitidos": hosts_permitidos,
            "origen_base_datos": db_urls,
        }, status=status.HTTP_200_OK)


