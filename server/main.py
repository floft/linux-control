import os
import traceback
import tornado.ioloop
import tornado.options
import tornado.httpserver

from tornado.options import define, options
from server.application import Application

define("port", default=8888, help="run on the given port", type=int)
define("debug", default=False, help="run in debug mode")
# For OAuth2 data
define("redis_host", default="127.0.0.1", help="database host")
define("redis_port", default="6379", help="database port")

def main():
    assert 'COOKIE_SECRET' in os.environ, "Must define COOKIE_SECRET environment variable"
    assert 'OAUTH_CLIENT_ID' in os.environ, "Must define OAUTH_CLIENT_ID environment variable"
    assert 'OAUTH_CLIENT_SECRET' in os.environ, "Must define OAUTH_CLIENT_SECRET environment variable"
    assert 'OAUTH_GOOGLE_SECRET' in os.environ, "Must define OAUTH_GOOGLE_SECRET environment variable"
    assert 'OAUTH_GOOGLE_URI' in os.environ, "Must define OAUTH_GOOGLE_URI environment variable"
    assert 'HTTP_AUTH_USER' in os.environ, "Must define HTTP_AUTH_USER environment variable"
    assert 'HTTP_AUTH_PASS' in os.environ, "Must define HTTP_AUTH_PASS environment variable"

    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.current().start()

if __name__ == "__main__":
    main()
