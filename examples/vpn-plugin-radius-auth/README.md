# vpn-plugin-radius-auth

Use Radius to auth with a username and password.

This can be handy for Ping, for example.

This script supports multiple radius servers with failover.
If no server responds correctly, authing will fail. Otherwise,
the first server to respond determines authing.

## Installation

You will need /usr/bin/python3 
(see the top-level README for why.
Use a symlink, or edit the shebang line if you don't/can't have this).

pip install -r requirements.txt

And of course, put vpn-plugin-radius-auth where you deem appropriate.

see ./vpn-plugin-radius-auth -h for details on location of config, dictionary,
and logs.

## Development

pip install -r dev-requirements.txt

`black -l 78 vpn_plugin_radius_auth.py`
`python -m doctest vpn_plugin_radius_auth.py`
`pylint vpn_plugin_radius_auth.py`

