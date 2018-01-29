#!/bin/bash
# Generate with `openssl rand -hex 30` for example
export COOKIE_SECRET=""
# Get these from https://console.cloud.google.com/apis/credentials
export OAUTH_CLIENT_ID=""
export OAUTH_CLIENT_SECRET=""
# For Dialogflow fullfillment
export HTTP_AUTH_USER=""
export HTTP_AUTH_PASS=""

python3 server.py --debug
