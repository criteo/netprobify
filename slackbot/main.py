#!/usr/bin/env python
"""Slackbot to request netprobify API."""

import json
import os
import re
import time

import requests
from requests import HTTPError, RequestException
from slackclient import SlackClient


def list_get_index(list_var, index, default=None):
    """Provide equivalent of dict().get()."""
    if index < len(list_var):
        return list_var[index]
    else:
        return default


def get_target(arguments, username):
    """Get targets.

    Keywoard arguments:
    arguments -- string containing the user's request
    username -- username who has done the request
    """
    if len(arguments) < 1:
        return get_help()

    # TODO: add filters

    try:
        response = requests.get(
            "http://netprobe01-am6.preprod.crto.in:8001/api/targets",
            headers={"apikey": os.environ.get("NETPROBIFY_TOKEN")},
        )
    except (HTTPError, RequestException) as error:
        raise RuntimeError("Error while contacting API") from error

    # We load data as JSON
    try:
        json_data = json.loads(response.content)
    except json.JSONDecodeError as error:
        raise RuntimeError("Error while decoding response from API") from error

    output = ""
    if not json_data:
        return "No targets set."

    output += "*Targets*\n"
    for target in json_data:
        output += "- dest=`{}".format(target.get("destination"))
        if target.get("dst_port"):
            output += ":{}".format(target.get("dst_port"))
        output += "`, proto=`{}`, ".format(target.get("type"))
        output += "owner=`{}`\n".format(target.get("owner"))

    return output


def add_target(arguments, username):
    """Add a target.

    Keywoard arguments:
    arguments -- string containing the user's request
    username -- username who has done the request
    """
    if len(arguments) < 2:
        return get_help()

    target = arguments[1]
    protocol_id = list_get_index(arguments, 2)

    # parse protocol
    need_port = False
    if protocol_id.lower() in ["tcp", "tcpsyn"]:
        protocol = "TCPsyn"
        need_port = True
    elif protocol_id.lower() in ["udp", "udpunreachable"]:
        protocol = "UDPunreachable"
        need_port = True
    elif protocol_id.lower() in ["icmp", "icmpping", "ping"]:
        protocol = "ICMPping"
    else:
        return get_help()

    json_post = {"hostname": target, "ip_payload_size": 0, "owner": username, "type": protocol}

    # add port if needed
    if protocol in ("TCPsyn", "UDPunreachable"):
        port = list_get_index(arguments, 3) if need_port else None
        try:
            json_post["dst_port"] = port
        except Exception as error:
            raise (error)

    try:
        response = requests.post(
            "http://netprobe01-am6.preprod.crto.in:8001/api/target",
            json=json_post,
            headers={"apikey": os.environ.get("NETPROBIFY_TOKEN")},
        )
    except (HTTPError, RequestException) as error:
        raise RuntimeError("Error while contacting API") from error

    return response.content.decode("utf-8")


def process_request(request, username):
    """Process request from Slack.

    Keywoard arguments:
    request -- string containing the user's request
    username -- username who has done the request
    """
    arguments = request.split(" ")

    if len(arguments) == 0:
        return get_help()
    elif arguments[0] == "add":
        return add_target(arguments, username)
    elif arguments[0] == "get":
        return get_target(arguments, username)

    return get_help()


def extract_request(message, slack_id):
    """Extract request from the message.

    Keywoard arguments:
    message -- user's message
    slack_id -- bot slack id
    """
    request = message.replace("{} ".format(slack_id), "").strip()
    request = re.sub(" +", " ", request)
    return request


def get_help():
    """Get the help message."""
    help_message = (
        "Usage: `@netprobify <command> <argument1> [argument2 ...]`\n\n"
        "Commands supported:\n"
        "   - `add <ip_address> | <hostname> <protocol> [port]` add a target\n\n"
        "   - `get` get the list of dynamic targets\n\n"
        "Protocol supported:\n"
        "   - `tcp` | `tcpsyn`\n"
        "   - `udp` | `udpunreachable`\n"
        "   - `icmp` | `ping` | `icmpping`\n"
    )
    return help_message


def slack_listener(slack_token):
    """Listen message from Slack.

    Keywoard arguments:
    slack_token -- token to communicate with Slack
    """
    slack_client = SlackClient(slack_token)
    connect_status = slack_client.rtm_connect(with_team_state=False)
    if connect_status:
        slack_id = "<@{}>".format(slack_client.api_call("auth.test")["user_id"])
        while True:
            result = slack_client.rtm_read()

            message_list = [
                r
                for r in result
                if r.get("type") == "message" and r.get("text", "").startswith(slack_id)
            ]

            for request in message_list:
                # get username
                print(request)
                user_info = slack_client.api_call("users.info", user=request["user"])
                username = user_info.get("user", {}).get("name")

                # get the command
                command = extract_request(request["text"], slack_id)

                # process the request
                response = process_request(command, username)  # TODO: find real username

                # answer to the request
                message = "<@{}>".format(request["user"])

                slack_client.api_call(
                    "chat.postMessage",
                    channel=request["channel"],
                    attachments=[
                        {"id": 1, "pretext": message, "color": "#1e73fc", "text": response}
                    ],
                )
            time.sleep(0.5)


def entrypoint():
    """Entrypoint."""
    slack_listener(os.environ.get("SLACK_TOKEN"))


entrypoint()
