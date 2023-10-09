'''
cisco-psirt-app
'''

import json
import requests
import config

client_key = config.client_key
client_secret = config.client_secret
webex_bot_id = config.webex_bot_id
webex_bot_key = config.webex_bot_key
webex_bot_room = config.webex_bot_room

# Authenticate to API
def authenticate_to_api(key, secret):
    data = {
        "Content-Type" : "application/x-www-form-urlencoded",
        "client_id" : key,
        "client_secret" : secret,
        "grant_type" : "client_credentials"
    }
    
    auth_data = requests.post("https://id.cisco.com/oauth2/default/v1/token", data=data)

    auth_json = json.loads(auth_data.text)
    return auth_json.get("access_token")

def collect_psirt_data(token):
    payload = {
        "Accept" : "application/json",
        "Authorization" : "Bearer " + token,
    }

    psirts_raw_data = requests.get("https://apix.cisco.com/security/advisories/v2/product?product=Cisco%20Firepower%20Threat%20Defense%20Software&pageSize=10", headers=payload)
    return json.loads(psirts_raw_data.text)

# Filter results
def filter_psirt_results(results):
    # Send to Webex
    def send_to_webex(details):
        headers = {
            "Authorization": "Bearer " + webex_bot_key,
            "Content-Type" : "application/json"
        }
        print(headers)
        message_details = {
            "roomId" : webex_bot_room,
            "text" : details,
        }
        print(message_details)
        p = requests.post("https://webexapis.com/v1/messages", headers=headers, json=message_details)
        print(p.text)

    advisory_list = results["advisories"]

    for advisory in advisory_list:
        webex_text = advisory["advisoryId"] + " // " + advisory["advisoryTitle"] + "\n" + advisory["publicationUrl"]
        print(webex_text)
        send_to_webex(webex_text)



if __name__ == "__main__":
    auth_token = authenticate_to_api(client_key, client_secret)

    psirt_data = collect_psirt_data(auth_token)

    filter_psirt_results(psirt_data)