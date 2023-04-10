import os

import requests


def slack_webhook(message):
    url = os.environ.get("SLACK_WEBHOOK_URL")
    payload = {'text': message}
    requests.post(url, json=payload, headers={'Content-Type': 'application/json'})
