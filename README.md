# Migrate Policy from Legacy Stateful Firewall and FQDN Egress to Distributed Cloud Firewall

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

## Output
The translator script will output several files that can then be used to configure the controller to leverage DCF.  Many of these are Terrform (HCL and JSON) for configuring the Aviatrix controller.  Others are CSV files to help review the translated policy.

```
aviatrix_distributed_firewall_policy_list.tf.json - Distributed Cloud Firewall Rule list for configuring the Aviatrix Platform
aviatrix_smart_group.tf.json - Smart Groups Terraform JSON for configuring the Aviatrix Platform
aviatrix_web_group.tf.json - Web Groups Terraform JSON for configuring the Aviatrix Platform
smartgroups.csv - Review the SmartGroup Configuration
unsupported_fqdn_rules.csv - Review the FQDN rules that were not translated because they seem to use an unsupported port/protocol
```

## Pushing Configuration to the Aviatrix Controller
Use Terraform to push the new configuration to the controller.
* It's recommended to push the new configuration to a lab controller prior to pushing to production.  A lab controller can be deployed without requiring any Aviatrix licensing to test the policy configuration.
* It's recommended to push the new configuration with a default catch-all of ALLOW to ensure that everything works as expected and then flip the Default Catch All to deny after the environment continues to be functional.
* Because Terraform is used for configuration, backing out of the configuration is as simple as a Terraform destroy.
* A main.tf file is created by the translation script, but this TF could be integrated with a broader IAC repository.  The main.tf assumes that the Aviatrix configuration is stored in environment variables in alignment with the Aviatrix Terraform Provider configuration.

```
terraform init
terraform apply
```

## Translation Methodology
### Objects that Translate to SmartGroups:
* Stateful Firewall Tags -> CIDR-type SmartGroups with the name matching the legacy tag name
* Single CIDRs that were referenced as a direct source/dest in a stateful firewall policy -> attempt to match with an existing tag if there is a perfect match, otherwise create a CIDR-based SmartGroup with the naming convention: “cidr_{CIDR}-{mask}”
* VPCs -> All VPCs have SmartGroups created with the following match critieria: “account, region, name” with the name of the smartgroup being the “vpcid_displayname”
 
### Objects that Translate to WebGroups:
* FQDN Tags - A single tag could create multiple webgroups.  We split out the Webgroups based on port/protocol match and action.  Naming convention is the name of the legacy FQDN tag with the proto/port appended.
* Unsupported FQDN Tags – DCF doesn’t currently support non-HTTP/TLS FQDN filtering.  The translator WILL IGNORE THESE POLICIES AND THEY WILL NEED TO BE CREATED MANUALLY.  Details of the rules can be found in the “unsupported_fqdn_rules.csv” output
* Disabled Tags – Disabled tags will create webgroups for the sake of translation, but it will not be used in any policies.  Details of the disabled tags can be found in the following script output.
 
### Translating the Policy:
Policy translation is broken up into 3 phases:

L4/Stateful Firewall Translation:
* Has significant policy optimizations. Policies that were previously duplicated on primary and HA gateways, or on source and destination gateways are de-duplicated since the rules are now global.
* Legacy Stateful Firewall rules could only have a single port/proto.  DCF can have a single proto, but multiple ports.  Policies that share the same source/dst/proto will be consolidated into a single rule with multiple ports.
* There are additional opportunities for optimization where a single destination shares the same source/proto/ports, but that is not implemented.

### FQDN Translation:
* Disabled tags are removed from evaluation.
* If a VPC has an enabled tag, it will create a policy for each port/proto combination with the source smartgroup as the VPC, the destination smartgroup as the built-in “Public Internet” smartgroup, and the webgroup with it’s port/proto combination.  This could mean multiple policies per VPC if there are multiple webgroups created per the translation above.
* An Egress catch-all policy is then created for all VPCs that have the same “base policy” for an FQDN tag.  This will be something like src: “multiple source smartgroups”, dst – “Public Internet”, no webgroup, deny all traffic to the built-in “Public Internet” smartgroup.
* Next VPCs in discovery mode will have two policies created – one for known web traffic ports, and one for all other traffic.
* src: “multiple source smartgroups”, dst – “Public Internet”, built-in “Any” webgroup, logging enabled, action: Allow, proto: tcp, ports: 80,443
* src: “multiple source smartgroups”, dst – “Public Internet”, logging enabled, action: Allow, proto: any
* Last, VPCs that are doing single-ip source nat, but don’t have any FQDN tags enabled will have an allow all policy for public internet access

### Catch-Alls:
* Since these VPCs may not be attached to a transit and doing L4 east-west policy, we have to make sure this maintains the existing security posture, but doesn’t break anything new.  A simple way to do this would be to create a set of deny’s for any VPC that has a stateful FW policy set to default deny, and then a single Allow all.  Many customers won’t want an Allow All as the final policy, though, so a more granular approach is taken.
* Catch all rules come in pairs – one with the smartgroups as the src, dst Any; and another with the src Any, dst Smartgroups
* VPCs are analyzed to determine whether they have stateful firewall policies or not.  If no stateful firewall policy is found for a VPC, it is assumed that that VPC should have an Allow all default posture.
There are 4 catch-alls created
* Has Stateful Firewall default deny action – create a policy for those VPCs to deny traffic in and out.
* Has Stateful Firewall default allow action – create a policy for those VPCs to allow traffic in and out.  Place this below the deny’s so that it isn’t shadowing.
* No Stateful firewall policy applied – Assume that L4 default action should be allow and create corresponding policies.  These are named as “Catch All Unknown” and should be manually reviewed.
* The Global Catch All.  This is the last rule, and is src/dst any/any.  It is currently set to “ALLOW” and can be switched to “DENY” after manual review of the translation.
 
### Other Notes:
* The global catch all is currently set to allow.
* All rules except the global catch all are set to log – independent of whether they were logging prior to migration.

## Important Notes
As of version 7.1, Distributed Cloud Firewall webgroups only support HTTP and TLS traffic for FQDN filtering.  The legacy FQDN filtering feature support non-HTTP/TLS traffic such as SSH and SMTP.  This will be supported with Webgroups in a future release.  In the meantime, the translator script will alert when it detects a policy that is not on either port 443 or port 80 and alert that it may not be compatible with the new DCF policy.  It is recommended to manually review these policies and address them with one of the following mechanisms:

1. Manually translate these policies to use an IP/CIDR based SmartGroup as the destination.
2. Leverage Webgroups and DCF for the majority of the policies, but leverage the legacy FQDN feature for non-HTTP/TLS policies until it is supported in Webgroups.  You can do this by creating a legacy FQDN Tag that has a 0.0.0.0/0 allow policy on TCP ports 443 and 80, and then explicit allows for the alternative ports.