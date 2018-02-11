import json
import tornado.gen

from tornado_http_auth import BasicAuthMixin
from pywakeonlan.wakeonlan import send_magic_packet
from server.base import BaseHandler

class DialogFlowHandler(BasicAuthMixin, BaseHandler):
    def initialize(self, credentials):
        self.credentials = credentials

    def check_xsrf_cookie(self):
        """
        Disable check since DialogFlow logs in via basic HTTP authentication
        """
        return True

    def prepare(self):
        self.get_authenticated_user(check_credentials_func=self.credentials.get, realm='Protected')

    def get(self):
        self.write("This is meant to be a webhook for DialogFlow")

    @tornado.gen.coroutine
    def get_wol_mac(self, userid, computer):
        laptop_mac, desktop_mac = yield self.get_macs(userid)

        if computer.strip().lower() == "laptop":
            return laptop_mac
        else:
            return desktop_mac

    @tornado.gen.coroutine
    def post(self):
        data = json.loads(self.request.body.decode('utf-8'))

        # Skip if already answered, e.g. saying "Hi!" will be fulfilled by "Small Talk"
        if 'fulfillmentText' in data['queryResult']:
            self.write(json.dumps({}))
            self.set_header("Content-type", "application/json")
            return

        # Make sure the user is logged in and provided a valid access token for a signed-up user
        if 'originalDetectIntentRequest' not in data or \
           'payload' not in data['originalDetectIntentRequest'] or \
           'user' not in data['originalDetectIntentRequest']['payload'] or \
           'accessToken' not in data['originalDetectIntentRequest']['payload']['user']:
            self.write(json.dumps({ "fulfillmentText": "You must be logged in." }))
            self.set_header("Content-type", "application/json")
            return

        userid = yield self.getUserIDFromToken(data['originalDetectIntentRequest']['payload']['user']['accessToken'])

        if not userid:
            print("Error: Invalid access token - userid:", userid, "data:", data)
            self.write(json.dumps({ "fulfillmentText": "Invalid access token." }))
            self.set_header("Content-type", "application/json")
            return

        response="Sorry, I'm not sure how to answer that."

        # Determine command/query and respond appropriately
        try:
            intent = data['queryResult']['intent']['displayName']
            params = data['queryResult']['parameters']

            if intent == "Computer Command":
                command = params['Command']
                computer = params['Computer']
                x = params['X']
                url = params['url']

                # Only command we handle is the WOL packet
                if command == "power on":
                    if computer:
                        mac = yield self.get_wol_mac(userid, computer)

                        if mac:
                            send_magic_packet(mac, port=9)
                            response = "Woke your "+computer
                        else:
                            response = "Your "+computer+" is not set up for wake-on-LAN"
                else:
                    if userid in self.clients and computer in self.clients[userid]:
                        response = "Will forward command to your "+computer
                        self.clients[userid][computer].write_message(json.dumps({
                            "command": { "command": command, "x": x, "url": url }
                        }))
                    else:
                        response = "Your "+computer+" is not currently online"

                    # TODO
                    # If this takes too long, then immediately respond "Command sent to laptop"
                    # and then do this: https://productforums.google.com/forum/#!topic/dialogflow/HeXqMLQs6ok;context-place=forum/dialogflow
                    # saving context and later returning response or something
            elif intent == "Computer Query":
                value = params['Value']
                x = params['X']
                computer = params['Computer']

                # Only query we handle is the "where is my laptop/desktop"
                if value == "where":
                    if computer:
                        if userid in self.clients and computer in self.clients[userid]:
                            ip = self.clients[userid][computer].ip
                            response = "Unknown location for your "+computer

                            if ip:
                                if ip == self.serverIp:
                                    response = "Your "+computer+" is at home"
                                else:
                                    data = self.gi.record_by_addr(ip)

                                    if data and "city" in data and "region_name" in data and "country_name" in data:
                                        city = data["city"]
                                        region = data["region_name"]
                                        country = data["country_name"]
                                        response = "Your "+computer+" is in "+city+", "+region+", "+country+" ("+ip+")"
                        else:
                            response = "Could not find location of your "+computer
                    else:
                        response = "Please specify which computer you are asking about"
                else:
                    if userid in self.clients and computer in self.clients[userid]:
                        response = "Will forward command to your "+computer
                        self.clients[userid][computer].write_message(json.dumps({
                            "query": { "value": value, "x": x }
                        }))
                    else:
                        response = "Your "+computer+" is not currently online"
        except KeyError:
            pass

        #"source": string,
        #"payload": { },
        #"outputContexts": [ { object(Context) } ],
        #"followupEventInput": { object(EventInput) },
        #"fulfillmentMessages": [ { response } ],
        json_response = json.dumps({ "fulfillmentText": response })
        self.write(json_response)
        self.set_header("Content-type", "application/json")

