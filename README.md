# cisco-psirt-app
Used to pull data from the Cisco OpenVuln API and post to a Webex room

[Screenshot of messages posted to Webex space](webex.png)

## Setup
1. Rename sample-config.py to config.py
2. Edit config.py and put your Cisco API keys and secrets in the file

```
client_key = "YOUR-CISCO-API-KEY-ID"
client_secret = "YOUR-CISCO-API-CLIENT-SECRET"
webex_bot_id = "YOUR-WEBEX-BOT-ID"
webex_bot_key = "YOUR-WEBEX-BOT-API-KEY"
webex_bot_room = "YOUR-WEBEX-ROOM"
```

## Usage
`python3 psirt.py`
