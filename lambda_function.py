import json
import logging
import requests
import boto3
import os
import random
from pathlib import Path
from profiler import profile

logger = logging.getLogger()
logger.setLevel(logging.INFO)


lambda_client = boto3.client('lambda')

db_service = boto3.resource("dynamodb")
client_mapping_table = db_service.Table(os.environ.get("client_mapping_table"))


@profile
def lambda_handler(event, context):
    # Posts the message of the user to Haptik bot configured
    client_id = event.get("client_id")
    user_name = event.get("user_name")
    email = event.get("email")
    auth_id = event.get("user")
    is_file = event.get("is_file")
    source = event.get("source")
    bot_creds = get_bot_creds(client_id)

    if not bot_creds:
        logger.error(f"Couldn't get bot creds of client id: {client_id}")
        return
    if is_file:
        file_type = event.get("file_type")
        file_link = event.get("file_link")
        send_attachment_to_haptik(
            bot_creds, user_name, email, auth_id, file_link, file_type, source)
    else:
        message = event.get("message")
        send_message_to_haptik(bot_creds, user_name, email, auth_id, message)
    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda!')
    }


def get_bot_creds(client_id):
    # Based on client id fetches the bot credentials from DB
    response = client_mapping_table.get_item(Key={"client_id": client_id})
    creds = {}
    if "Item" in response:
        creds["bot_business"] = response.get("Item").get("bot_business")
        creds["bot_auth"] = response.get("Item").get("bot_auth")
        creds["bot_client_id"] = response.get("Item").get("bot_client_id")
        creds["slack_auth"] = response.get("Item").get("slack_auth")
        creds["teams_client_id"] = response.get("Item").get("teams_client_id")
        creds["teams_client_secret"] = response.get("Item").get("teams_client_secret")
        creds["teams_scope"] = response.get("Item").get("teams_scope")
    else:
        logger.error(f"Bot Creds are missing for client_id: {client_id}")
    return creds


def send_message_to_haptik(bot_creds, user_name, email, auth_id, message):
    # Sends message to Haptik
    logger.info(f"[Haptik Helper] Incoming Message to send: {message}")
    send_message_url = os.environ.get("send_message_url")

    headers = {
        "Content-Type": "application/json",
        "client-id": bot_creds.get("bot_client_id"),
        "Authorization": bot_creds.get("bot_auth")
    }
    data = {
        "user": {"auth_id": auth_id},
        "message_body": message,
        "message_type": 0,
        "business_id": int(bot_creds.get("bot_business")),
    }
    logger.info(
        f"[Haptik Function] Trying to send a message.\n\n{data}\n\n{headers}")
    response = requests.post(
        send_message_url, data=json.dumps(data), headers=headers)
    logger.info(f"[Send Message] Response: {response.text}")

    if (
        response.status_code == 403
        and response.json().get("error_message", "") == "user is not registered"
    ):
        logger.info(
            "[Haptik Function] Creating user and try sending a message")
        create_user_response = create_haptik_user(
            bot_creds, user_name, email, auth_id)
        logger.info(create_user_response.json())
        if create_user_response.status_code == 200:
            logger.info(
                "[Haptik Function] Created a user, Trying to send a message")
            response = requests.post(
                send_message_url, data=json.dumps(data), headers=headers
            )
            logger.info(f"Send Message Response: {response.json()}")
        else:
            logger.error("Couldn't create a user for sending the message")
            return

    return response.json().get("message_id")


def create_haptik_user(bot_creds, user_name, email, auth_id):
    # Creates a new user with Haptik
    logger.info(
        f"[Haptik Helper] Creating a user with name: {user_name} and auth_id: {auth_id}"
    )
    create_user_url = os.environ.get("create_user_url")
    payload = {"auth_id": auth_id, "name": user_name, "email": email}
    headers = {
        "Content-Type": "application/json",
        "client-id": bot_creds.get("bot_client_id"),
        "Authorization": bot_creds.get("bot_auth")
    }
    return requests.request("POST", create_user_url, json=payload, headers=headers)


def send_attachment_to_haptik(bot_creds, user_name, email, auth_id, file_link, file_type, source):
    # Sends an attachment to bot
    logger.info(f"handling attachment with file type: {file_type}")
    if (source.lower() not in ["teams", "slack"] or
            file_type not in ["png", "jpeg", "jpg", "docx", "pdf"]):
        return

    if source.lower() == "slack":
        file_headers = {
            "Authorization": bot_creds["slack_auth"]
        }
    elif source.lower() == "teams":
        teams_auth = get_teams_auth(bot_creds)
        file_headers = {
            "Authorization": teams_auth
        }
    # Get the file contents
    file_response = requests.request("GET", file_link, headers=file_headers)

    file_type = file_type.lower()
    # set the message type and files
    if file_type in ["png", "jpeg", "jpg"]:
        message_type = "1"
        # Create a local file
        with open("/tmp/slack_image.png", "wb") as handler:
            handler.write(file_response.content)
        files = [("file", open("/tmp/slack_image.png", "rb"))]
    elif file_type in ["docx", "pdf"]:
        message_type = "52"
        r_int = random.randint(1,9999999)
        file_name = Path(f'/tmp/file{r_int}.{file_type}')
        file_name.write_bytes(file_response.content)
        files = [("file", (f"file{r_int}.{file_type}", open(
            f"/tmp/file{r_int}.{file_type}", "rb"), f'application/{file_type}'))]

    # Send File to Haptik
    payload = {"auth_id": auth_id, "business_id": bot_creds["bot_business"],
               "message_type": message_type}
    headers = {"Authorization":  bot_creds["bot_auth"],
               "client-id": bot_creds["bot_client_id"]}
    send_file_url = os.environ.get("send_file_url")
    send_file = requests.request(
        "POST", send_file_url, headers=headers, data=payload, files=files)
    logger.info(f"Send file API returned: {send_file.status_code}")
    logger.info(f"Response of the send file is: {send_file.content}")
    if (
        send_file.status_code == 403
        and send_file.json().get("error_message", "") == "user is not registered"
    ):
        logger.info(
            "[Haptik Function] Creating user and try sending a file")
        create_user_response = create_haptik_user(
            bot_creds, user_name, email, auth_id)
        logger.info(f"Create user response: {create_user_response.json()}")
        if create_user_response.status_code == 200:
            logger.info(
                "[Haptik Function] Created a user, Trying to send a file")
            send_file = requests.request(
                "POST", send_file_url, headers=headers, data=payload, files=files)
            logger.info(f"Send File Response: {send_file.json()}")
        else:
            logger.error(f"Couldn't create a user for sending the message")
            return
    elif send_file.status_code not in [200,201]:
        return "Sending attachment to haptik failed"

    return send_file.json().get("message_id")


def get_teams_auth(creds):
    """
    Generates the auth token
    """
    url = os.environ.get('teams_auth_token_url')

    payload = {
        "grant_type": "client_credentials",
        "client_id": creds["teams_client_id"],
        "client_secret": creds["teams_client_secret"],
        "scope": creds["teams_scope"]
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    response = requests.request("POST", url, headers=headers, data=payload)
    if response.status_code == 200:
        return "Bearer " + response.json().get("access_token")
    else:
        logger.error(f"couldn't generate auth token:\n{response.text}")
