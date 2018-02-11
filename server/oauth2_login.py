import tornado.gen
import tornado.auth

from server.base import BaseHandler

class GoogleOAuth2LoginHandler(BaseHandler,
        tornado.auth.GoogleOAuth2Mixin):
    @tornado.gen.coroutine
    def get(self):
        if self.get_argument('code', False):
            access = yield self.get_authenticated_user(
                redirect_uri='https://wopto.net:42770/linux-control/auth/login',
                code=self.get_argument('code'))
            user = yield self.oauth2_request(
                "https://www.googleapis.com/oauth2/v1/userinfo",
                access_token=access["access_token"])
            # Save the user
            userid = yield self.getUserID(user['email'])

            # If not, create the user
            if not userid:
                userid = yield self.createUser(user["email"])

            # If user already in the database, add the ID in our cookie
            # (required for OAuth2 linking to user account for instance)
            self.set_secure_cookie('id', str(userid))

            self.redirect('/linux-control/account')
        else:
            yield self.authorize_redirect(
                redirect_uri='https://wopto.net:42770/linux-control/auth/login',
                client_id=self.settings['google_oauth']['key'],
                scope=['profile', 'email'],
                response_type='code',
                extra_params={'approval_prompt': 'auto'})

class LogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie('id')
        self.redirect('/linux-control')
