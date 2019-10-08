"""api to manage on the go targets."""

import logging
import os
import sys
from datetime import datetime, timedelta

import connexion
import pkg_resources
import yaml
from pykwalify.core import Core

from netprobify import common
from netprobify.settings import DEFAULT_ADDRESS_FAMILY

log_api = logging.getLogger(__name__)
targets_list = []
shared_targets_list = None
global_module_name = None
groups = []
token = None
max_targets = 10
target_lifetime = timedelta(days=1)
max_target_lifetime = timedelta(days=30)

UNIQUE_KEYS = ["hostname", "address_family", "type", "dst_port", "ip_payload_size"]


def auth_token(apikey, required_scopes=None):
    """Check token validity.

    Keyword arguments:
    apikey -- token provided by the user
    """
    if apikey == token:
        return {"sub": "user"}
    else:
        return None


def compare_targets(target_a, target_b):
    """Compare two targets to make sure they are unique.

    Keyword arguments:
    target_a -- target to compare
    target_b -- target to compare
    """
    return all(target_a[k] == target_b[k] for k in UNIQUE_KEYS)


def match_target_attribute(target, attribute, value):
    """Check if target matches with attribute and value.

    Returns true if value is None.
    Returns true if attribute is None.
    > because some values or ignored and are optional example port doesn't matter if ICMP

    Keyword arguments:
    attribute -- attribute to check
    value -- value in the attribute
    """
    return True if not value or not target.get(attribute) else target[attribute] == value


def get_targets(hostname=None, owner=None, address_family=None):
    """Get targets by owner and/or hostname and/or address family or all.

    Keyword arguments:
    hostname -- target list filtered by hostname
    owner -- target list filtered by owner
    address_family -- target list filtered by address family
    """
    # we get the last target list from the shared list
    global targets_list
    targets_list = shared_targets_list[global_module_name]

    result = []
    if all(attr is None for attr in (hostname, owner, address_family)):
        result = [target.copy() for target in targets_list]
    else:
        # we add targets tha matches the filters
        result.extend(
            [
                target.copy()
                for target in targets_list
                if match_target_attribute(target, "hostname", hostname)
                and match_target_attribute(target, "owner", owner)
                and match_target_attribute(target, "address_family", address_family)
            ]
        )

    for target in result:
        target["lifetime"] = str(target["lifetime"])

    return result


def add_target(target):
    """Add a target in the list.

    Keyword arguments:
    target -- dict containing target definition
    """
    global shared_targets_list

    # we get the last target list from the shared list
    global targets_list
    targets_list = shared_targets_list[global_module_name]

    if len(targets_list) >= max_targets:
        return "Conflict", 409, {"x-error": "Maximum number of target allowed reached"}

    # set default value, to make comparison easier
    target["address_family"] = target.get("address_family", DEFAULT_ADDRESS_FAMILY)
    target["type"] = target.get("type", "ICMPping")
    target["dst_port"] = target.get("dst_port", 80)
    target["type"] = target.get("type", 0)
    target["ip_payload_size"] = target.get("ip_payload_size", 0)
    if target.get("lifetime"):
        target["lifetime"] = common.explode_datetime(target.get("lifetime"))
    else:
        target["lifetime"] = target_lifetime

    if target["lifetime"] > max_target_lifetime:
        target["lifetime"] = max_target_lifetime
        log_api.warning(
            "{} Target lifetime set is superior than maximum allowed.".format(target["hostname"])
        )

    # we record the target only if it is unique
    existing = [t for t in targets_list if compare_targets(t, target)]
    if len(existing):
        return "Conflict", 409, {"x-error": "Conflict: already exists"}

    destination = common.resolve_hostname(target["hostname"], target["address_family"])

    if destination is None:
        return (
            "Internal Server Error",
            "500",
            {"x-error": "Internal Server Error: DNS resolution failed"},
        )

    targets_list.append(
        {
            "owner": target["owner"],
            "hostname": target["hostname"],
            "type": target["type"],
            "dst_port": target["dst_port"],
            "ip_payload_size": target["ip_payload_size"],
            "state": "in production",
            "alert_level": "no_alert",
            "destination": destination,
            "address_family": target["address_family"],
            "nb_packets": target.get("nb_packets", 20),
            "timeout": 1,
            "groups": groups,
            "creation_date": datetime.now(),
            "lifetime": target_lifetime,
        }
    )

    shared_targets_list[global_module_name] = targets_list


def remove_target():
    """Remove a target in the list.

    Keyword arguments:
    target -- dict containing target definition
    """
    global targets_list, shared_targets_list

    # we get the last target list from the shared list
    targets_list = shared_targets_list[global_module_name]

    # we get the attribute to locate the target to delete
    target = connexion.request.json

    # we keep only the targets not matching the attributes of the target we want to delete
    new_targets_list = [
        t
        for t in targets_list
        if not all(match_target_attribute(t, key, target[key]) for key in UNIQUE_KEYS)
    ]

    # we check if we deleted a target successfully
    if len(targets_list) - len(new_targets_list) >= 1:
        targets_list = new_targets_list
        return "OK", 200, {"x-error": "OK: the target has been deleted"}
    else:
        return "Not Found", 404, {"x-error": "Not Found: the target does not exist"}

    shared_targets_list[global_module_name] = targets_list


# TODO def request_dns_resolution


def start(
    targets, module_name, logging_level, config_file="api.yaml", schema_file="api.schema.yaml"
):
    """Start the API.

    Keyword arguments:
    targets -- shared target list
    module_name -- module name set by the main code to separate targets
    logging_level -- level logging set in the global config file
    config_file -- name of the config file for the API
    schema_file -- schema of the config file for the API
    """
    global shared_targets_list
    global global_module_name
    global token
    global max_targets
    global target_lifetime
    global max_target_lifetime

    # initiate list in dict from Manager (shared variable with main code)
    targets[module_name] = []

    # transform config file to absolute path
    entry_path = os.path.dirname(os.path.abspath(sys.argv[0]))
    config_file_abs = os.path.join(entry_path, config_file)

    # load inventory configuration
    if not os.path.exists(config_file_abs):
        log_api.info("No configuration file for api module")
        return

    # getting a reference of this list and module name
    shared_targets_list = targets
    global_module_name = module_name

    # validate yaml config with the schema
    schema = pkg_resources.resource_filename(__name__, schema_file)
    yaml_validator = Core(source_file=config_file_abs, schema_files=[schema])
    yaml_validator.validate(raise_exception=True)

    # if config file exists, we load it and parse it
    with open(config_file_abs, "r") as conf_file:
        try:
            conf = yaml.safe_load(conf_file)
            log_api.debug("network_devices configuration loaded")
        except Exception as error:
            log_api.error("Unable to load config file: {0}".format(error))

    listen_address = conf.get("listen_address", "0.0.0.0")
    listen_port = conf.get("listen_port", 8009)
    groups.extend(conf.get("groups", []))
    token = conf.get("token")
    max_targets = conf.get("max_targets", 10)
    target_lifetime = common.explode_datetime(conf.get("target_lifetime", "1d"))
    max_target_lifetime = common.explode_datetime(conf.get("max_target_lifetime", "30d"))

    # starting the API
    log_api.logging_level = "WARNING"
    app = connexion.FlaskApp(__name__, server="tornado", debug=False)
    app.add_api("api.swagger.yml")
    app.run(host=listen_address, port=listen_port, debug=False)
