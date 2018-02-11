#!/bin/bash
# Generate with `openssl rand -hex 30` for example
export COOKIE_SECRET=""
# Get these from https://console.cloud.google.com/apis/credentials
export OAUTH_CLIENT_ID=""
export OAUTH_CLIENT_SECRET=""
# For the OAuth2 provider, generate secret with `pwgen 30 1`
export OAUTH_GOOGLE_ID="google-assistant"
export OAUTH_GOOGLE_SECRET=""
export OAUTH_GOOGLE_URI="https://oauth-redirect.googleusercontent.com/r/YOUR-ACTION-ID"
# For Dialogflow fullfillment
export HTTP_AUTH_USER=""
export HTTP_AUTH_PASS=""

cd /path/to/linux-control
python3 -m server.main --debug
