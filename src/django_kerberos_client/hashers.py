"""
django-kerberos-client - authentication module for Django applications
Copyright (C) 2024 - Acsone
License: AGPLv3
"""

import logging
from django.core.exceptions import ImproperlyConfigured
from django.utils.encoding import force_bytes
from django.contrib.auth.hashers import BasePasswordHasher
import kerberos
from . import app_settings


class KerberosHasher(BasePasswordHasher):
    '''
    Secure password hashing using the kerberos algorithm
    '''
    algorithm = 'kerberos'

    def default_realm(self):
        return app_settings.DEFAULT_REALM

    def service_principal(self):
        if not app_settings.SERVICE_PRINCIPAL:
            raise ImproperlyConfigured(
                'KERBEROS_SERVICE_PRINCIPAL is not defined')
        return app_settings.SERVICE_PRINCIPAL

    def verify(self, password, encoded):
        algorithm, principal = encoded.split('$', 2)
        assert algorithm == self.algorithm
        principal = force_bytes(principal)
        password = force_bytes(password)
        try:
            return kerberos.checkPassword(
                principal, password,
                self.service_principal(),
                self.default_realm())
        except kerberos.KrbError as e:
            logging.getLogger(__name__).error(
                'Password validation for principal %r failed %s', principal, e)
            return False
