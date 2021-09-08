#!/usr/bin/env python3

"""
vpn-plugin-radius-auth

authenticate against radius with username and password.
Use with auth-script-openvpn
"""

import logging
from logging.handlers import RotatingFileHandler
import os
import sys

import configargparse
from pyrad.client import Client
from pyrad.dictionary import Dictionary
import pyrad.packet


def get_logger(location, level=logging.INFO):
    """
    Accept location (file-like object),
    optional level (logging level, defaulting to logging.INFO).
    Return a logger object.
    """
    logger = logging.getLogger("vpn_plugin_radius_auth")
    logger.setLevel(level)

    channel = logging.StreamHandler()
    channel_fmt = logging.Formatter("%(levelname)s - %(message)s")
    channel.setFormatter(channel_fmt)
    logger.addHandler(channel)

    filehandle = RotatingFileHandler(location, maxBytes=10240, backupCount=10)
    filehandle_fmt = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s", "%Y-%m-%dT%H:%M:%S"
    )
    filehandle.setFormatter(filehandle_fmt)
    logger.addHandler(filehandle)

    return logger


def write_dictionary(location: str) -> bool:
    """
    Accept location (file-like object).
    Write a default radius dictionary to the location if it does not exist.
    return True
    """
    rad_dictionary = """
    ATTRIBUTE       User-Name                               1       string
    ATTRIBUTE       User-Password                           2       string encrypt=1
    ATTRIBUTE       NAS-IP-Address                          3       ipaddr
    """

    # Dedent
    dict_fmt = "\n".join(line.strip() for line in rad_dictionary.split("\n"))

    if not os.path.exists(location):
        with open(location, "w", encoding="utf-8") as my_dictionary:
            my_dictionary.write(dict_fmt)
    return location


def _is_authorized_p(server: str, credentials: dict, logger):
    """
    Accept server (str), credentials (dict), logger.
    return True if server authorizes credentials,
    False is server denies authorization,
    None on error.
    """
    port = credentials["port"]
    dictionary = credentials["dictionary"]
    config = credentials["config"]
    username = credentials["username"]
    nas_ip = credentials["nas_ip"]
    password = credentials["password"]
    dry_run = credentials["dry_run"]
    encoded_secret = bytes(credentials["shared_secret"], encoding="utf-8")
    logger.info(
        "Creating radius client of %s:%d using dictionary %s for config %s",
        server,
        port,
        dictionary,
        config,
    )
    client = Client(
        server=server,
        secret=encoded_secret,
        dict=Dictionary(dictionary),
        authport=port,
        timeout=10,
    )

    logger.info(
        "Creating AuthPacket for user %s from %s",
        username,
        nas_ip,
    )
    request = client.CreateAuthPacket(
        code=pyrad.packet.AccessRequest,
        User_Name=username,
        NAS_IP_Address=nas_ip,
    )
    request["User-Password"] = request.PwCrypt(password)

    logger.info(
        "sending AccessRequest for user %s to %s:%d",
        username,
        server,
        port,
    )
    if dry_run is True:
        reply_code = pyrad.packet.AccessAccept
    else:
        try:
            reply_code = client.SendPacket(request).code
        except Exception as err:
            logger.error(
                "error sending AccessRequest for user %s to %s:%d: %s: %s",
                username,
                server,
                port,
                type(err),
                err,
            )
            return None
    logger.info(
        "got reply code %d for user %s from %s:%d",
        reply_code,
        username,
        server,
        port,
    )
    return reply_code == pyrad.packet.AccessAccept


def any_and_not_false(iterable: list) -> bool:
    """
    Accept iter.
    A reimplementation of any,
    with the differnce that the first False short-circuits.

    The purpose of this is to short circuit
    the moment we get an auth or a denial from a radius server,
    while letting non-responses fail over to the next server.

    >>> any_and_not_false([False, True, None])
    False
    >>> any_and_not_false([False, None, True])
    False
    >>> any_and_not_false([True, False, None])
    True
    >>> any_and_not_false([True, None, False])
    True
    >>> any_and_not_false([None, True, False])
    True
    >>> any_and_not_false([None, False, False])
    False
    >>> any_and_not_false([None, None])
    False
    """
    for item in iterable:
        if item:
            return True
        if item is False:
            return False
    return False


def is_authorized_p(credentials: dict, logger) -> bool:
    """
    Accept credentials (dict).
    return True if credentials are authorized.
    else False.
    """
    c = credentials

    if not write_dictionary(c["dictionary"]):
        return False

    return any_and_not_false(
        _is_authorized_p(server, c, logger) for server in c["servers"]
    )


def write_auth_file(authorized: bool, auth_file: str) -> bool:
    """
    Accept authorized (bool),
    auth_file (file-like object).
    Write 1 to auth_file if authorized is True;
    otherwise write 0 to auth_file.
    FIXME what happens to openvpn if we can't write the file?
    """

    auth_message = str(int(authorized)) + "\n"
    with open(auth_file, "w", encoding="utf-8") as output:
        output.write(auth_message)


def main():
    """
    Parse args,
    get environment,
    set umask,
    pass off to is_authorized_p and write_auth_file.
    """

    parser = configargparse.ArgumentParser()
    parser.add_argument(
        "-c",
        "--config",
        help="""Use config file CONFIG.
        Defaults to /etc/openvpn/radius/auth.conf""",
        is_config_file=True,
        default="/etc/openvpn/radius/auth.conf",
    )
    parser.add_argument(
        "-S",
        "--servers",
        help="""Servers to send packets to, in order of preference.
        Config file syntax is 'servers = [server_1, server_2]'""",
        required=True,
        metavar="SERVER",
        nargs="+",
    )
    parser.add_argument(
        "-p",
        "--port",
        help="""Port to send radius packets to.
        Default is 1812.""",
        default=1812,
        type=int,
    )
    parser.add_argument(
        "-s",
        "--shared-secret",
        help="Radius shared secret",
        required=True,
    )
    parser.add_argument(
        "-i",
        "--nas-ip",
        help="""IP to report to the radius server where this packet comes from.
        Defaults to 127.0.0.1""",
        default="127.0.0.1",
    )
    parser.add_argument(
        "-d",
        "--dictionary-location",
        help="""filesystem location of the radius dictionary to use.
        Defaults to /etc/openvpn/radius-vpn.dictionary.
        This file will be written with default settings if it does not exist.""",
        default="/etc/openvpn/radius-vpn.dictionary",
        dest="dictionary",
    )
    parser.add_argument(
        "-L",
        "--log-location",
        help="""Where to log to.
        Defaults to /var/log/openvpn/vpn-plugin-radius-auth.log
        """,
        default="/var/log/openvpn/vpn-plugin-radius-auth.log",
    )
    parser.add_argument(
        "-D",
        "--dry-run",
        help="""Assemble and print packet;
        do not send it.
        Treat auth as successful.
        """,
        action="store_true",
    )

    args = parser.parse_args()
    logger = get_logger(location=args.log_location)

    cred_items = [
        "servers",
        "port",
        "shared_secret",
        "nas_ip",
        "dictionary",
        "dry_run",
    ]
    credentials = {k: v for k, v in vars(args).items() if k in cred_items}
    credentials["username"] = os.environ.get("username", "fake_user")
    credentials["password"] = os.environ.get("password", "fake_password")
    credentials["config"] = os.environ.get("config", "fake_config")
    auth_control_file = os.environ.get(
        "auth_control_file", "fake_auth_control_file"
    )

    # We will be writing logs, auth_file, and possibly a dictionary.
    # all should be 644 permissions.
    os.umask(0o133)
    # Any exception means we should not authorize...
    try:
        authorized = is_authorized_p(credentials, logger)
    except Exception as err:
        logger.error(err)
        authorized = False
    logger.info("user %s authorized: %s", credentials["username"], authorized)
    try:
        write_auth_file(authorized, auth_control_file)
    except Exception as err:
        logger.error(err)
    # ... and we always want to exit successfully
    sys.exit(0)


if __name__ == "__main__":
    main()
