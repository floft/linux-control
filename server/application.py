import os
import json
import redis
import GeoIP
import logging
import collections
import tornado.web
import tornado.httpclient
import oauth2.store.redisdb

from tornado.options import define, options
from server.site_main import MainHandler
from server.site_account import AccountHandler
from server.dialogflow import DialogFlowHandler
from server.oauth2_provider import OAuth2Handler, OAuth2SiteAdapter
from server.oauth2_login import GoogleOAuth2LoginHandler, LogoutHandler
from server.websocket import ClientConnection

class Application(tornado.web.Application):
    def __init__(self):
        #
        # Database
        #
        self.redis = redis.StrictRedis(host=options.redis_host, port=options.redis_port, db=0)

        #
        #
        # Dictionary of dictionaries of open websockets indexed by user id then computer name
        # e.g. { 1: { "laptop": ClientConnection(), "desktop": ClientConnection() ], ... }
        #
        # Recursive: https://stackoverflow.com/a/19189356/2698494
        rec_dd = lambda: collections.defaultdict(rec_dd)
        self.clients = rec_dd()

        #
        # Looking up location from IP
        #
        self.gi = GeoIP.GeoIP("/usr/share/GeoIP/GeoIPCity.dat", GeoIP.GEOIP_STANDARD)

        # Get external IP of server
        self.serverIp = None
        http_client = tornado.httpclient.AsyncHTTPClient()
        http_client.fetch("https://api.ipify.org?format=json", self._saveIP)

        #
        # OAuth2 provider
        #
        token_store = oauth2.store.redisdb.TokenStore(
            host=options.redis_host, port=options.redis_port, db=0, prefix="oauth2")
        client_store = oauth2.store.redisdb.ClientStore(
            host=options.redis_host, port=options.redis_port, db=0, prefix="oauth2")

        # Allow Google Assistant to request access
        client_store.add_client(
            client_id=os.environ['OAUTH_GOOGLE_ID'],
            client_secret=os.environ['OAUTH_GOOGLE_SECRET'],
            redirect_uris=[
                os.environ['OAUTH_GOOGLE_URI'],
                "https://developers.google.com/oauthplayground" # For debugging
            ],
            authorized_grants=[
                oauth2.grant.AuthorizationCodeGrant.grant_type,
                oauth2.grant.RefreshToken.grant_type
            ],
            authorized_response_types=["code"]
        )

        # Generator of tokens
        token_generator = oauth2.tokengenerator.Uuid4()

        # OAuth2 controller
        self.auth_controller = oauth2.Provider(
            access_token_store=token_store,
            auth_code_store=token_store,
            client_store=client_store,
            token_generator=token_generator
        )
        self.auth_controller.authorize_path = '/linux-control/oauth/auth'
        self.auth_controller.token_path = '/linux-control/oauth/token'

        # Add Client Credentials to OAuth2 controller
        self.site_adapter = OAuth2SiteAdapter()
        self.auth_controller.add_grant(oauth2.grant.AuthorizationCodeGrant(
            expires_in=86400, site_adapter=self.site_adapter)) # 1 day
        # Add refresh token capability and set expiration time of access tokens to 30 days
        self.auth_controller.add_grant(oauth2.grant.RefreshToken(
            expires_in=2592000, reissue_refresh_tokens=True))

        # For DialogFlow
        credentials = { os.environ['HTTP_AUTH_USER']: os.environ['HTTP_AUTH_PASS'] }

        #
        # Tornado
        #
        handlers = [
            (r"/linux-control", MainHandler),
            (r"/linux-control/", MainHandler),
            (r"/linux-control/account", AccountHandler),
            (r"/linux-control/dialogflow", DialogFlowHandler, dict(credentials=credentials)),
            (r"/linux-control/auth/login", GoogleOAuth2LoginHandler),
            (r"/linux-control/auth/logout", LogoutHandler),
            (r"/linux-control/con", ClientConnection),
            (self.auth_controller.authorize_path, OAuth2Handler, dict(provider=self.auth_controller)),
            (self.auth_controller.token_path, OAuth2Handler, dict(provider=self.auth_controller)),
            #(r"/linux-control/foo", FooHandler, dict(provider=self.auth_controller))
        ]
        settings = dict(
            websocket_ping_interval=60, # ping every minute
            websocket_ping_timeout=60*3, # close connection if no pong
            cookie_secret=os.environ['COOKIE_SECRET'],
            xsrf_cookies=True,
            google_oauth={
                'key': os.environ['OAUTH_CLIENT_ID'],
                'secret': os.environ['OAUTH_CLIENT_SECRET']
            },
            login_url="/linux-control/auth/login",
            debug=options.debug,
        )
        super(Application, self).__init__(handlers, **settings)

    def _saveIP(self, response):
        """
        Callback for saving server ip
        """
        if response.error:
            logging.error("Could not get server IP: "+str(response.error))
        else:
            data = json.loads(response.body)

            if "ip" in data:
                self.serverIp = data["ip"]
                logging.info("Server IP: "+str(self.serverIp))

