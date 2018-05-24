import tornado.gen
import tornado.auth

from server.base import BaseHandler

class GoogleOAuth2LoginHandler(BaseHandler,
        tornado.auth.GoogleOAuth2Mixin):
    @tornado.gen.coroutine
    def get(self):
        if self.get_argument('code', False):
            access = yield self.get_authenticated_user(
                redirect_uri='https://'+self.config['server']+self.config['root']+'/auth/login',
                code=self.get_argument('code'))
            user = yield self.oauth2_request(
                "https://www.googleapis.com/oauth2/v1/userinfo",
                access_token=access["access_token"])

            # If we have a whitelist, make sure the user is on it
            if "whitelist_emails" not in self.config or \
                not isinstance(self.config["whitelist_emails"], list) or \
                user['email'] in self.config["whitelist_emails"]:

                # Save the user
                userid = yield self.getUserID(user['email'])

                # If not, create the user
                if not userid:
                    userid = yield self.createUser(user["email"])

                # If user already in the database, add the ID in our cookie
                # (required for OAuth2 linking to user account for instance)
                self.set_secure_cookie('id', str(userid))

                # Redirect to a particular page (probably "oauth/auth") if
                # specified, otherwise the account page
                login_redirect = self.get_secure_cookie("login_redirect")
                self.clear_cookie("login_redirect")

                if login_redirect:
                    login_redirect = login_redirect.decode("utf-8")
                    self.redirect(login_redirect)
                else:
                    self.redirect(self.config['root']+'/account')

            else:
                self.redirect(self.config['root']+'/auth/denied')
        else:
            yield self.authorize_redirect(
                redirect_uri='https://'+self.config['server']+self.config['root']+'/auth/login',
                client_id=self.settings['google_oauth']['key'],
                scope=['profile', 'email'],
                response_type='code',
                extra_params={'approval_prompt': 'auto'})

class LogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie('id')
        self.redirect(self.config['root'] + '/')

class DeniedHandler(BaseHandler):
    def get(self):
            self.write("""
<html>
    <head><title>Linux Control</title></head>
    <body>
        <h1>Linux Control: Access Denied</h1>

        <div>Your email does not appear to be in the whitelist, so you are not
        allowed to create an account on this server.</div>

        <div><a href="{root}/auth/login">Try logging in again</a></div>
    </body>
</html>
            """.format(root=self.config["root"]))
