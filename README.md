# Migrate Policy from Legacy Stateful Firewall and FQDN Egress to DCF

## Export Legacy Policy Bundle
This should be run against the controller and will export a ZIP file.
```
❯ python3 export_legacy_policy_bundle.py --help                                                     
usage: export_legacy_policy_bundle.py [-h] -i CONTROLLER_IP -u USERNAME [-p PASSWORD] [-o OUTPUT] [-w]

Collects Controller IP, username, and password.

options:
  -h, --help            show this help message and exit
  -i CONTROLLER_IP, --controller_ip CONTROLLER_IP
                        Controller IP address
  -u USERNAME, --username USERNAME
                        Username
  -p PASSWORD, --password PASSWORD
                        Password
  -o OUTPUT, --output OUTPUT
                        Output file name
  -w, --any_web         Download the Any Webgroup ID. Controller version must be v7.1 or greater
```

## Translator
1. Create 2 folders in the directory where where `translator.py` lives. `./input` and `./output`.  Optionally create a 3rd `./debug`
2. Extract the exported legacy policy bundle into input.
3. Log into the target controller and grab the "Any Webgroup" ID.  This is a required input for `translator.py` as it is unique per controller.  The "Any" Webgroup is available starting in controller version 7.1.
3. Run `translator.py`.

```
❯ python3 translator.py --help                 
usage: translator.py [-h] [--loglevel {DEBUG,INFO,WARNING,ERROR,CRITICAL}] [--internet-sg-id INTERNET_SG_ID]
                     [--anywhere-sg-id ANYWHERE_SG_ID] --any-webgroup-id ANY_WEBGROUP_ID
                     [--default-web-port-ranges DEFAULT_WEB_PORT_RANGES [DEFAULT_WEB_PORT_RANGES ...]]
                     [--global-catch-all-action {PERMIT,DENY}] [--config-path CONFIG_PATH] [--output-path OUTPUT_PATH]
                     [--debug-path DEBUG_PATH]

Your script description here

options:
  -h, --help            show this help message and exit
  --loglevel {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        Set the logging level.
  --internet-sg-id INTERNET_SG_ID
                        Internet security group ID.
  --anywhere-sg-id ANYWHERE_SG_ID
                        Anywhere security group ID.
  --any-webgroup-id ANY_WEBGROUP_ID
                        Any webgroup ID.
  --default-web-port-ranges DEFAULT_WEB_PORT_RANGES [DEFAULT_WEB_PORT_RANGES ...]
                        Default web port ranges. Can provide multiple, space separated. Can provide a range by comma-delimiting.
  --global-catch-all-action {PERMIT,DENY}
                        Global catch all action. Choices are 'PERMIT' or 'DENY'.
  --config-path CONFIG_PATH
                        Path to the configuration files.
  --output-path OUTPUT_PATH
                        Path to save output files.
  --debug-path DEBUG_PATH
                        Path for debug files.
```