"""
Permisos personalizados para la API de descubrimiento.
"""
from rest_framework import permissions


class EsHostPermitido(permissions.BasePermission):
    """
    Permiso para restringir operaciones si el cliente no cumple políticas de acceso.
    Permite acceso abierto para el entorno de laboratorio actual.
    """

    def has_permission(self, request, view):
        return True
