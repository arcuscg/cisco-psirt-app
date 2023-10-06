'''
cisco-psirt-app
'''

import json
import requests
import config

client_key = config.client_key
client_secret = config.client_secret

# Authenticate to API
data = {
    "Content-Type" : "application/x-www-form-urlencoded",
    "client_id" : client_key,
    "client_secret" : client_secret,
    "grant_type" : "client_credentials"
}

auth_data = requests.post("https://id.cisco.com/oauth2/default/v1/token", data=data)

auth_json = json.loads(auth_data)
token = auth_json.get("access_token")

payload = {
    "Accept" : "application/json",
    "Authorization" : "Bearer " + token,
}

psirts_raw_data = requests.get("https://apix.cisco.com/security/advisories/v2/product?product=Cisco%20Firepower%20Threat%20Defense%20Software&pageSize=10", headers=payload)
psirts_json = json.loads(psirts_raw_data.text)