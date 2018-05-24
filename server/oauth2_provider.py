import logging
import tornado.template
import oauth2.grant
import oauth2.web.tornado
import oauth2.tokengenerator

from oauth2.web import AuthorizationCodeGrantSiteAdapter
from server.base import BaseHandler

class OAuth2Handler(BaseHandler, oauth2.web.tornado.OAuth2Handler):
    """
    Require the user to be authenticated when going to the authorization page
    """
    def check_xsrf_cookie(self):
        """
        Only check via our auth form, not when Google gets refresh tokens, etc.

        Note: lazy evaluation means token_path check has to be first
        """
        return self.request.path == self.provider.token_path or \
                super(OAuth2Handler, self).check_xsrf_cookie()

    def get(self):
        # Only require login for auth, not regenerating tokens
        if self.request.path == self.provider.token_path or self.get_current_user():
            response = self._dispatch_request()
            self._map_response(response)
        else:
            self.set_secure_cookie("login_redirect", self.request.uri)
            self.redirect(self.config["root"]+"/auth/login")

    def post(self):
        if self.request.path == self.provider.token_path or self.get_current_user():
            response = self._dispatch_request()
            self._map_response(response)
        else:
            self.set_secure_cookie("login_redirect", self.request.uri)
            self.redirect(self.config["root"]+"/auth/login")

class OAuth2SiteAdapter(AuthorizationCodeGrantSiteAdapter):
    """
    This adapter renders a confirmation page so the user can confirm the auth
    request.

    From: http://python-oauth2.readthedocs.io/en/latest/tornado.html
    """

    CONFIRMATION_TEMPLATE = """
<html>
    <head>
        <title>OAuth2 Authorization</title>
        <style>
        input[type="submit"] {
            font-size: 1.17em; /* probably ~h3 */
            border: 0;
            outline: 0;
            color: white;
            margin: 5px;
            padding: 20px 100px;
            width: 100%;
            background: DodgerBlue;
            box-shadow: none;
            border-radius: 0px;
        }
        </style>
    </head>
    <body>
        <h3>Do you want to allow Google Assistant access?</h3>

        <form method="GET" action="{{ url }}">
            <input type="hidden" name="scope" value="{{ scope }}" />
            <input type="hidden" name="state" value="{{ state }}" />
            <input type="hidden" name="redirect_uri" value="{{ redirect_uri }}" />
            <input type="hidden" name="response_type" value="{{ response_type }}" />
            <input type="hidden" name="client_id" value="{{ client_id }}" />
            <input type="submit" name="confirm" value="Confirm" />
            <input type="submit" name="deny" value="Deny" />
            {% module xsrf_form_html() %}
        </form>
    </body>
</html>
    """
    def render_from_string(self, request, tmpl, **kwargs):
        """
        From: https://github.com/tornadoweb/tornado/issues/564
        """
        namespace = request.handler.get_template_namespace()
        namespace.update(kwargs)
        return tornado.template.Template(tmpl).generate(**namespace)

    def render_auth_page(self, request, response, environ, scopes, client):
        scope = request.get_param("scope")
        state = request.get_param("state")
        redirect_uri = request.get_param("redirect_uri")
        response_type = request.get_param("response_type")
        client_id = request.get_param("client_id")

        if scope:
            scope = tornado.escape.xhtml_escape(scope)
        else:
            scope = ""

        if state:
            state = tornado.escape.xhtml_escape(state)
        else:
            state = ""

        if redirect_uri:
            redirect_uri = tornado.escape.xhtml_escape(redirect_uri)
        else:
            redirect_uri = ""

        if response_type:
            response_type = tornado.escape.xhtml_escape(response_type)
        else:
            response_type = ""

        if client_id:
            client_id = tornado.escape.xhtml_escape(client_id)
        else:
            client_id = ""

        response.body = self.render_from_string(request, self.CONFIRMATION_TEMPLATE,
            url=request.path,
            scope=scope,
            state=state,
            redirect_uri=redirect_uri,
            response_type=response_type,
            client_id=client_id)

        return response

    def authenticate(self, request, environ, scopes, client):
        if request.method == "GET":
            if request.get_param("confirm") == "Confirm":
                # Must be a tuple with the second an integer user id
                # https://github.com/wndhydrnt/python-oauth2/blob/3645093f653d5527f83767f8bb5161f9fd03ad83/oauth2/grant.py#L319
                return ({}, request.handler.get_current_user())
        raise oauth2.error.UserNotAuthenticated

    def user_has_denied_access(self, request):
        if request.method == "GET":
            if request.get_param("deny") == "Deny":
                return True
        return False
