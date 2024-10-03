import logging
import pytest
import json

import kerberos
from django.contrib.auth.models import User


@pytest.fixture
def kerberos_mock(request, mocker):
    a = {}
    d = (
        'kerberos.authGSSServerInit',
        'kerberos.authGSSServerStep',
        'kerberos.authGSSServerResponse',
        'kerberos.authGSSServerUserName',
        'kerberos.authGSSServerClean',
        'kerberos.checkPassword'
    )
    for name in d:
        if hasattr(request, 'param') and name in request.param:
            continue
        a[name] = mocker.patch(name)
    return a


def test_login_no_header(client, settings, kerberos_mock):
    client.get('/login/')
    for mock in kerberos_mock.values():
        assert mock.call_count == 0


@pytest.mark.parametrize('kerberos_mock', ['kerberos.authGSSServerInit'], indirect=True)
def test_login_missing_keytab(client, settings, kerberos_mock, caplog):
    resp = client.get('/login/', HTTP_AUTHORIZATION='Negotiate coin')
    for key, mock in kerberos_mock.items():
        assert mock.call_count == 0
    assert b'keytab problem' in resp.content
    assert 'keytab problem' in caplog.text


def test_login(client, db, settings, kerberos_mock, caplog):
    caplog.set_level(logging.INFO)
    kerberos_mock['kerberos.authGSSServerInit'].side_effect = kerberos.KrbError('coin')
    response = client.get('/login/', HTTP_AUTHORIZATION='Negotiate xxxx')
    assert response.status_code == 500
    assert b'exception during authGSSServerInit' in response.content
    assert 'exception during authGSSServerInit' in caplog.text
    assert b'coin' in response.content
    kerberos_mock['kerberos.authGSSServerInit'].side_effect = None
    caplog.clear()

    kerberos_mock['kerberos.authGSSServerInit'].return_value = 0, None
    response = client.get('/login/', HTTP_AUTHORIZATION='Negotiate xxxx')
    assert response.status_code == 500
    assert b'authGSSServerInit result is non-one' in response.content
    assert 'authGSSServerInit result is non-one' in caplog.text
    caplog.clear()

    kerberos_mock['kerberos.authGSSServerInit'].return_value = 1, None
    kerberos_mock['kerberos.authGSSServerStep'].side_effect = kerberos.KrbError('coin')
    response = client.get('/login/', HTTP_AUTHORIZATION='Negotiate xxxx')
    assert response.status_code == 500
    assert b'exception during authGSSServerStep' in response.content
    assert 'exception during authGSSServerStep' in caplog.text
    assert b'coin' in response.content
    kerberos_mock['kerberos.authGSSServerStep'].side_effect = None
    caplog.clear()

    kerberos_mock['kerberos.authGSSServerStep'].return_value = 0
    response = client.get('/login/', HTTP_AUTHORIZATION='Negotiate xxxx')
    assert response.status_code == 401

    kerberos_mock['kerberos.authGSSServerStep'].return_value = 1
    kerberos_mock['kerberos.authGSSServerUserName'].side_effect = kerberos.KrbError('coin')
    response = client.get('/login/', HTTP_AUTHORIZATION='Negotiate xxxx')
    assert response.status_code == 500
    assert b'exception during authGSSServerUserName' in response.content
    assert 'exception during authGSSServerUserName' in caplog.text
    assert b'coin' in response.content
    kerberos_mock['kerberos.authGSSServerUserName'].side_effect = None
    caplog.clear()

    kerberos_mock['kerberos.authGSSServerUserName'].return_value = 'john.doe@EXAMPLE.COM'
    kerberos_mock['kerberos.authGSSServerResponse'].return_value = 'yyyy'
    response = client.get('/login/', HTTP_AUTHORIZATION='Negotiate xxxx')
    assert response.status_code == 302
    assert 'principal john.doe@EXAMPLE.COM has no local user' in caplog.text
    caplog.clear()

    user = User.objects.create(username='john.doe@example.com')
    assert '_auth_user_id' not in client.session
    response = client.get('/login/', HTTP_AUTHORIZATION='Negotiate xxxx')
    assert response.status_code == 302
    assert response['WWW-Authenticate'] == 'Negotiate yyyy'
    assert 'principal john.doe@EXAMPLE.COM has no local user' not in caplog.text
    assert client.session['_auth_user_id'] == str(user.id)
    client.logout()
    user.delete()
    assert User.objects.count() == 0
    caplog.clear()

    settings.KERBEROS_BACKEND_CREATE = True
    assert '_auth_user_id' not in client.session
    response = client.get('/login/', HTTP_AUTHORIZATION='Negotiate xxxx')
    assert response.status_code == 302
    assert 'principal john.doe@EXAMPLE.COM has no local user' not in caplog.text
    assert User.objects.count() == 1
    user = User.objects.get()
    assert not user.is_staff
    assert not user.is_superuser
    assert client.session['_auth_user_id'] == str(user.id)
    assert 'got ticket for principal john.doe@EXAMPLE.COM' in caplog.text
    client.logout()
    caplog.clear()

    settings.KERBEROS_BACKEND_ADMIN_REGEXP = 'john.doe'
    assert '_auth_user_id' not in client.session
    response = client.get('/login/', HTTP_AUTHORIZATION='Negotiate xxxx')
    assert response.status_code == 302
    assert 'principal john.doe@EXAMPLE.COM has no local user' not in caplog.text
    assert User.objects.count() == 1
    user = User.objects.get()
    assert user.is_staff
    assert user.is_superuser
    assert client.session['_auth_user_id'] == str(user.id)
    assert 'got ticket for principal john.doe@EXAMPLE.COM' in caplog.text
    assert 'giving superuser power to principal \'john.doe@EXAMPLE.COM\'' in caplog.text
    client.logout()
    caplog.clear()

    assert '_auth_user_id' not in client.session
    response = client.get('/login/', HTTP_AUTHORIZATION='Negotiate xxxx', HTTP_X_REQUESTED_WITH='XMLHttpRequest')
    assert response.status_code == 200
    assert json.loads(response.content.decode('ascii')) is True


def test_password_backend(db, settings, kerberos_mock, caplog):
    from django.contrib.auth import authenticate

    settings.KERBEROS_DEFAULT_REALM = 'EXAMPLE.COM'
    settings.KERBEROS_SERVICE_PRINCIPAL = 'HTTP/SERVICE.EXAMPLE.COM@EXAMPLE.COM'

    m = kerberos_mock['kerberos.checkPassword']
    m.return_value = False
    assert authenticate(username='john.doe', password='password') is None
    assert User.objects.count() == 0

    m.return_value = True
    assert authenticate(username='john.doe', password='password') is None
    assert User.objects.count() == 0

    user = User.objects.create(username='john.doe@example.com')
    assert authenticate(username='john.doe', password='password') == user
    user.delete()

    assert User.objects.count() == 0
    settings.KERBEROS_BACKEND_CREATE = True
    new_user = authenticate(username='john.doe', password='password')
    assert new_user
    assert User.objects.count() == 1
    assert new_user.username == 'john.doe@example.com'
    assert not new_user.has_usable_password()

    settings.KERBEROS_KEEP_PASSWORD = True
    new_user = authenticate(username='john.doe', password='password')
    assert User.objects.count() == 1
    assert new_user.username == 'john.doe@example.com'
    assert new_user.has_usable_password()
    assert new_user.check_password('password')

    caplog.clear()
    m.side_effect = kerberos.KrbError('coin')
    assert authenticate(username='john.doe', password='password') is None
    assert 'password validation for principal %r failed coin' % u'john.doe@EXAMPLE.COM' in caplog.text
