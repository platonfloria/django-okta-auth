import logging
import secrets

from django.contrib import messages
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.messages.api import MessageFailure
from django.http import (
    HttpResponseBadRequest,
    HttpResponseRedirect,
    HttpResponseServerError,
)
from django.shortcuts import redirect, render
from django.urls import reverse
from django.urls.exceptions import NoReverseMatch
from django.http import HttpResponse

from .conf import Config

from urllib.parse import urljoin, urlparse, urlencode, quote
from .exceptions import DjangoOktaAuthException

logger = logging.getLogger(__name__)


def login(request):
    config = Config()

    nonce = secrets.token_urlsafe(10)
    state = secrets.token_urlsafe(10)

    base_auth_url = urljoin(config.org_url, config.okta_authorize_url)
    base_auth_url = urlparse(base_auth_url)._replace(
        query=urlencode({
            'client_id': config.client_id,
            'redirect_uri': config.get_redirect_url(request),
            'response_type': 'code',
            'state': state,
            'scope': config.scopes,
        })
    ).geturl()

    response = redirect(base_auth_url)

    response.set_cookie('okta-oauth-nonce', nonce)
    response.set_cookie('okta-oauth-state', state)
    return response


def callback(request):
    config = Config()

    if request.method == "POST":
        return HttpResponseBadRequest("Method not supported")

    if "error" in request.GET:
        error_description = request.GET.get(
            "error_description", "An unknown error occurred."
        )

        return HttpResponse(error_description, status=401)

    code = request.GET["code"]
    state = request.GET["state"]

    # Get state and nonce from cookie
    cookie_state = request.COOKIES["okta-oauth-state"]
    cookie_nonce = request.COOKIES["okta-oauth-nonce"]

    # Verify state
    if state != cookie_state:
        return HttpResponseBadRequest(
            "Value {} does not match the assigned state".format(state)
        )

    try:
        user = authenticate(request, auth_code=code, nonce=cookie_nonce)
    except DjangoOktaAuthException as e:
        return HttpResponse(str(e), status=403)

    auth_login(request, user)

    try:
        redirect_url = reverse(config.login_redirect_url)
    except NoReverseMatch:
        redirect_url = config.login_redirect_url

    return redirect(redirect_url)


def logout(request):
    auth_logout(request)
    return HttpResponseRedirect(reverse("okta_oauth2:login"))


def _delete_cookies(response):
    # The Okta Signin Widget/Javascript SDK aka "Auth-JS" automatically generates
    # state and nonce and stores them in cookies. Delete authJS/widget cookies
    response.delete_cookie("okta-oauth-state")
    response.delete_cookie("okta-oauth-nonce")
    response.delete_cookie("okta-oauth-redirect-params")
