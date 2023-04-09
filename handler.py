import json
import logging

import boto3

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
        table = dynamodb.Table("serverless-websocker-connections")
        table.delete_item(Key={"connection_id": connection_id})
        return {"statusCode": 200, "body": "Disconnection successful."}

    else:
        logger.error("Connection manager receive unrecognized eventType '{}'")
        return {"statusCode": 500, "body": "Unrecognized eventType"}


def default_message(event, context):
    logger.info("Unrecognized WebSocket action received.")
    return {"statusCode": 400, "body": "Unrecognized WebSocket action."}


def send_message(event, context):
    body = json.loads(event.get("body", ""))
    for attribute in ["content"]:
        if attribute not in body:
            logger.debug(f"Failed: '{attribute}' not in message dict")
            return {"statusCode": 400, "body": f"'{attribute} not in message dict"}

    table = dynamodb.Table("serverless-websocket-connection")
    response = table.scan(ProjectionExpression="connection_id")
    items = response.get("Items", [])
    connections = [x["connection_id"] for x in items if "connection_id" in x]

    message = {"content": body["content"]}
    logger.debug(f"Broadcasting message: {message}")
    data = {"messages": [message]}
    for connection_id in connections:
        endpoint_url = f"https://{event['requestContext']['domain']}/{event['requestContext']['stage']}"
        gatewayapi = boto3.client("apigatewaymanagementapi", endpoint_url=endpoint_url)
        gatewayapi.post_to_connection(ConnectionId=connection_id, Data=json.dumps(data).encode('utf-8'))
    return {"statusCode": 200, "body": "Message sent to all connections."}

def ping(event, context):
    response = {
        "statusCode": 200,
        "body": "PONG"
    }
    return response
