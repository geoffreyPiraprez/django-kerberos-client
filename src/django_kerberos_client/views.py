"""
django-kerberos-client - authentication module for Django applications
Copyright (C) 2024 - Acsone
License: AGPLv3
"""

import logging

import kerberos

from django import http
from django.template.response import TemplateResponse
from django.conf import settings
from django.views.generic.base import View
from django.contrib import messages
from django.utils.translation import gettext_lazy as _

from django.contrib.auth import authenticate, login as auth_login

from . import app_settings


class NegotiateView(View):
    NEXT_URL_FIELD = 'next'
    unauthorized_template = 'django_kerberos_client/unauthorized.html'
    error_template = 'django_kerberos_client/error.html'

    def __init__(self, *args, **kwargs):
        self.logger = logging.getLogger(__name__)
        self.principal = None
        super().__init__(*args, **kwargs)

    def challenge(self, request, *args, **kwargs):
        response = TemplateResponse(request, self.unauthorized_template, status=401)
        response['WWW-Authenticate'] = 'Negotiate'
        return response

    def host(self, request):
        return app_settings.HOSTNAME or request.get_host().split(':')[0]

    def is_ajax(self, request):
        return request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest'

    def principal_valid(self, request, *args, **kwargs):
        self.logger.info('got ticket for principal %s', self.principal)
        user = authenticate(principal=self.principal)
        next_url = (request.POST.get(self.NEXT_URL_FIELD) or request.GET.get(self.NEXT_URL_FIELD) or
                    settings.LOGIN_REDIRECT_URL)
        if user:
            self.login_user(request, user)
        if self.is_ajax(request):
            return http.HttpResponse('true' if user else 'false', content_type='application/json')
        if not user:
            self.logger.warning('Principal %s has no local user', self.principal)
            messages.warning(request, _('Principal %s authentication failed') % self.principal)
            unauthorized_template = 'django_kerberos_client/unauthorized.html'
            return TemplateResponse(request, unauthorized_template, status=401)
        return http.HttpResponseRedirect(next_url)

    def login_user(self, request, user):
        auth_login(request, user)

    def negotiate(self, request, *args, **kwargs):
        '''Try to authenticate the user using SPNEGO and Kerberos'''

        if 'HTTP_AUTHORIZATION' in request.META:
            kind, authstr = request.META['HTTP_AUTHORIZATION'].split(' ', 1)
            if kind == 'Negotiate':
                service = 'HTTP@%s' % self.host(request)
                self.logger.debug('using service name %s', service)
                self.logger.debug('Negotiate authstr %r', authstr)
                try:
                    result, context = kerberos.authGSSServerInit(service)
                except kerberos.KrbError as e:
                    self.logger.warning('An exception occured when initializing server-side GSSAPI '
                                        'operations: %s, certainly a keytab problem', e)
                    details = ('An exception occured when initializing server-side GSSAPI: %s, certainly a '
                               'keytab problem' % e)
                    return TemplateResponse(request, self.error_template,
                                            context={'details': details}, status=500)
                # ensure context is finalized
                try:
                    if result != 1:
                        self.logger.warning('authGSSServerInit result is non-one: %s', result)
                        details = 'authGSSServerInit result is non-one: %s' % result
                        return TemplateResponse(request, self.error_template,
                                                context={'details': details}, status=500)
                    try:
                        r = kerberos.authGSSServerStep(context, authstr)
                    except kerberos.KrbError as e:
                        self.logger.warning('exception during authGSSServerStep: %s', e)
                        details = 'exception during authGSSServerStep: %s' % e
                        return TemplateResponse(request, self.error_template,
                                                context={'details': details}, status=500)
                    if r == 1:
                        gssstring = kerberos.authGSSServerResponse(context)
                    else:
                        return self.challenge(request, *args, **kwargs)
                    try:
                        self.principal = kerberos.authGSSServerUserName(context)
                    except kerberos.KrbError as e:
                        self.logger.warning('exception during authGSSServerUserName: %s', e)
                        details = 'exception during authGSSServerUserName: %s' % e
                        return TemplateResponse(request, self.error_template,
                                                context={'details': details}, status=500)
                finally:
                    kerberos.authGSSServerClean(context)
                response = self.principal_valid(request, *args, **kwargs)
                if response:
                    response['WWW-Authenticate'] = 'Negotiate %s' % gssstring
                    return response
        return self.challenge(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        return self.negotiate(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return self.negotiate(request, *args, **kwargs)

login = NegotiateView.as_view()
