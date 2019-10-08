"""Common functions."""

import json
from requests import HTTPError, RequestException


def request_api(request, session):
    """Request an API and return data in json format.

    Keyword arguments:
    request -- URL request
    session -- requests.session object
    """
    try:
        response = session.get(request)
        response.raise_for_status()
    except (HTTPError, RequestException) as error:
        raise RuntimeError("Error while contacting API") from error

    # We load data as JSON
    try:
        json_data = json.loads(response.text)
    except json.JSONDecodeError as error:
        raise RuntimeError("Error while decoding response from API") from error

    return json_data
