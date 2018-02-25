import os
import sys
import yaml
import logging
import traceback
import tornado.ioloop
import tornado.options
import tornado.httpserver

from tornado.options import define, options
from server.application import Application

define("debug", default=False, help="run in debug mode")

def main():
    # Parse config
    if len(sys.argv) < 2:
        raise RuntimeError("python3 -m server.main config.yaml [--debug]")

    configFile = sys.argv[1]
    config = {}

    with open(configFile, "r") as f:
        config = yaml.load(f)

    assert "server" in config, "Must define server in config"
    assert "root" in config, "Must define root in config"
    assert "port" in config, "Must define port in config"
    assert "whitelist_emails" in config, "Must define whitelist_emails in config"
    assert "redis_host" in config, "Must define redis_host in config"
    assert "redis_port" in config, "Must define redis_port in config"
    assert "cookie_secret" in config, "Must define cookie_secret in config"
    assert "oauth_client_id" in config, "Must define oauth_client_id in config"
    assert "oauth_client_secret" in config, "Must define oauth_client_secret in config"
    assert "oauth_google_secret" in config, "Must define oauth_google_secret in config"
    assert "oauth_google_uri" in config, "Must define oauth_google_uri in config"
    assert "http_auth_user" in config, "Must define http_auth_user in config"
    assert "http_auth_pass" in config, "Must define http_auth_pass in config"

    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application(config))
    http_server.listen(config["port"])
    tornado.ioloop.IOLoop.current().start()

if __name__ == "__main__":
    # For now, show info
    logging.getLogger().setLevel(logging.INFO)

    # Run the server
    main()
