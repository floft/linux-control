#!/bin/bash
# The user ID given in the web browser for your account
export ID=""
# Get from logging in from a web browser
export TOKEN=""

python3 -m client.main --debug
