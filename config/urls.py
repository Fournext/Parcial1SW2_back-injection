"""
Configuración de URLs del proyecto principal.
"""
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('backend_genvulnai.urls')),
]
