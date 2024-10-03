"""
django-kerberos-client - authentication module for Django applications
Copyright (C) 2024 - Acsone
License: AGPLv3
"""

import sys
from django.conf import settings

class AppSettings():
    __PREFIX = 'KERBEROS_'
    __DEFAULTS = {
        'BACKEND_CREATE': False,
        'BACKEND_ADMIN_REGEXP': None,
        'DEFAULT_REALM': None,
        'SERVICE_PRINCIPAL': '',
        'HOSTNAME': None,
        'KEEP_PASSWORD': False,
    }

    def __getattr__(self, name):
        if name not in self.__DEFAULTS:
            raise AttributeError
        return getattr(settings, self.__PREFIX + name, self.__DEFAULTS[name])

app_settings = AppSettings()
app_settings.__name__ = __name__
sys.modules[__name__] = app_settings
