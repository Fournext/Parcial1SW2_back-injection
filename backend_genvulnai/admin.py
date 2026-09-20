"""
Registro de modelos en el panel de administración de Django.
"""
from django.contrib import admin
from backend_genvulnai.models import (
    DiscoveryScan,
    AIChannel,
    NetworkObservation,
    AttackSession,
    AttackTurn,
    AllowedTargetURL
)


@admin.register(DiscoveryScan)
class DiscoveryScanAdmin(admin.ModelAdmin):
    list_display = ('id', 'target_url', 'status', 'created_at', 'finished_at')
    list_filter = ('status', 'created_at')
    search_fields = ('target_url', 'id', 'marcador')
    readonly_fields = ('id', 'created_at', 'started_at', 'finished_at')


@admin.register(AIChannel)
class AIChannelAdmin(admin.ModelAdmin):
    list_display = ('url', 'method', 'protocol', 'input_mode', 'confidence', 'created_at')
    list_filter = ('protocol', 'method', 'input_mode', 'response_mode')
    search_fields = ('url', 'prompt_field')


@admin.register(NetworkObservation)
class NetworkObservationAdmin(admin.ModelAdmin):
    list_display = ('method', 'request_url', 'response_status', 'contains_marker', 'created_at')
    list_filter = ('contains_marker', 'method', 'response_status')
    search_fields = ('request_url',)


@admin.register(AllowedTargetURL)
class AllowedTargetURLAdmin(admin.ModelAdmin):
    list_display = ('url', 'activa', 'descripcion', 'created_at')
    list_filter = ('activa', 'created_at')
    search_fields = ('url', 'descripcion')

