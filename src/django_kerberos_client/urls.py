"""
django-kerberos-client - authentication module for Django applications
Copyright (C) 2024 - Acsone
License: AGPLv3
"""

from django.urls import re_path
from . import views

urlpatterns = [
    re_path(r'^login/$', views.login, name='kerberos-login'),
]
