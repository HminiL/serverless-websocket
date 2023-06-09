import json
import logging

import boto3

import utils

logger = logging.getLogger("handler_logger")
logger.setLevel(logging.DEBUG)

dynamodb = boto3.resource("dynamodb")


def connection_manager(event, context):
    connection_id = event["requestContext"].get("connectionId")

    if event["requestContext"]["eventType"] == "CONNECT":
        logger.info("Connect requested")
        # generate connection_id
        table = dynamodb.Table("serverless-websocket-connections")
        table.put_item(Item={"connection_id": connection_id})
        return {"statusCode": 200, "body": "Connect successful"}

    elif event["requestContext"]["eventType"] == "DISCONNECT":
        logger.info("Disconnect request")
        # delete connection_id
        table = dynamodb.Table("serverless-websocket-connections")
        table.delete_item(Key={"connection_id": connection_id})
        return {"statusCode": 200, "body": "Disconnection successful."}

    else:
        logger.error("Connection manager receive unrecognized eventType '{}'")
        return {"statusCode": 500, "body": "Unrecognized eventType"}


def send_connection_message(event, context):
    logger.info("Received event: " + json.dumps(event, indent=2))
    if not event["Records"]:
        logger.error("No records in event")
        return {"statusCode": 500, "body": "No records in event"}
    if event["Records"][0]["eventName"] == "INSERT":
        utils.slack_webhook("유저 등장 두둥")
    elif event["Records"][0]["eventName"] == "DELETE":
        utils.slack_webhook("유저 퇴장 두둥")
    else:
        logger.error("Unrecognized event name.")
        return {"statusCode": 500, "body": "Unrecognized event name."}


def default_message(event, context):
    logger.info("Unrecognized WebSocket action received.")
    return {"statusCode": 400, "body": "Unrecognized WebSocket action."}


def send_message(event, context):
    body = json.loads(event.get("body", ""))
    for attribute in ["content"]:
        if attribute not in body:
            logger.debug(f"Failed: '{attribute}' not in message dict")
            return {"statusCode": 400, "body": f"'{attribute} not in message dict"}

    table = dynamodb.Table("serverless-websocket-connections")
    response = table.scan(ProjectionExpression="connection_id")
    items = response.get("Items", [])
    connections = [x["connection_id"] for x in items if "connection_id" in x]

    message = {"content": body["content"]}
    logger.debug(f"Broadcasting message: {message}")
    data = {"messages": [message]}
    for connection_id in connections:
        endpoint_url = f"https://{event['requestContext']['domainName']}/{event['requestContext']['stage']}"
        gatewayapi = boto3.client("apigatewaymanagementapi", endpoint_url=endpoint_url)
        gatewayapi.post_to_connection(ConnectionId=connection_id, Data=json.dumps(data).encode('utf-8'))
    return {"statusCode": 200, "body": "Message sent to all connections."}


def ping(event, context):
    response = {
        "statusCode": 200,
        "body": "PONG"
    }
    return response
