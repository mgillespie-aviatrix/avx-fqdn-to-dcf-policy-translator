import argparse
import getpass
import requests
import json
import zipfile
import io
import os

requests.packages.urllib3.disable_warnings()

def get_arguments():
    # Creates argument parser object
    parser = argparse.ArgumentParser(description='Collects Controller IP, username, and password.')
    # Adds arguments to the parser
    parser.add_argument('-i', '--controller_ip', help='Controller IP address', required=True)
    parser.add_argument('-u', '--username', help='Username', required=True)
    parser.add_argument('-p', '--password', help='Password', required=False)
    parser.add_argument('-o', '--output', help='Output file name', default='legacy_policy_bundle.zip')
    parser.add_argument('-w', '--any_web', help='Download the Any Webgroup ID. Controller version must be v7.1 or greater', action='store_true')

    args = parser.parse_args()

    # If password isn't given as an argument, ask for it and don't echo it in the console
    if args.password is None:
        args.password = getpass.getpass('Password: ')

    return args

def login(controller_ip, controller_user, controller_password):
    # Format the URL for the controller API
    url = "https://{}/v2/api".format(controller_ip)

    # Define payload to send for login
    payload = {'action': 'login',
               'username': controller_user,
               'password': controller_password}

    headers = {}

    try:
        # Make a POST request to the URL with the payload
        response = requests.post(url, headers=headers, data=payload, verify=False)
        
        # Check if response status is not 200 (HTTP OK), and if so, raise an error
        response.raise_for_status()
    except requests.exceptions.HTTPError as errh:
        print ("Http Error:", errh)
    except requests.exceptions.ConnectionError as errc:
        print ("Error Connecting:", errc)
    except requests.exceptions.Timeout as errt:
        print ("Timeout Error:", errt)
    except requests.exceptions.RequestException as err:
        print ("Oops: Something Else", err)
    # Return the CID from the response
    return response.json()["CID"]

def aviatrix_api_call(controller_ip, path, cid, params = {},stream=False):
    # print(cid)
    try:
        if "/v2.5/" in path:
            headers = {"Authorization":"cid {}".format(cid)}
            response = requests.get("https://{}{}".format(controller_ip,path),params = params, headers = headers, verify=False)
        else:
            params['CID'] = cid
            response = requests.get("https://{}{}".format(controller_ip,path),params = params, stream=stream, verify=False)
        
        # Check if response status is not 200 (HTTP OK), and if so, raise an error
        response.raise_for_status()
    except requests.exceptions.HTTPError as errh:
        print ("Http Error:", errh)
    except requests.exceptions.ConnectionError as errc:
        print ("Error Connecting:", errc)
    except requests.exceptions.Timeout as errt:
        print ("Timeout Error:", errt)
    except requests.exceptions.RequestException as err:
        print ("Oops: Something Else", err)
    return response

def get_gateway_details(controller_ip, cid):
    print("Getting gateway details.")
    response = aviatrix_api_call(controller_ip,"/v2/api?action=list_vpcs_summary",cid)
    return response.json()

def get_any_webgroup_id(controller_ip, cid):
    print("Getting Any-Web webgroup.")
    response = aviatrix_api_call(controller_ip,"/v2.5/api/app-domains",cid)
    webgroup = [x for x in response.json()['app_domains'] if x['name'] == "Any-Web"]
    return webgroup

def get_tf_resources(controller_ip, resource, cid):
    print("Getting {} TF resource config.".format(resource))
    response = aviatrix_api_call(controller_ip,"/v2/api?action=export_terraform_resource",cid,params = {"resource":resource},stream=True )
    try:
        z = zipfile.ZipFile(io.BytesIO(response.content))
        z.extract("{}.tf".format(resource))
    except:
        print("Could not extract TF resource {}".format(resource))

def main():
    # Fetch arguments
    args = get_arguments()

    # Use provided arguments to login and get CID
    cid = login(args.controller_ip, args.username, args.password)
   
    # Get gateway details using the CID
    gateway_details = get_gateway_details(args.controller_ip, cid)
    # Write the gateway details to the output file as JSON
    with open('gateway_details.json', 'w') as f:
        json.dump(gateway_details, f, indent=1)

    if args.any_web == True:
        any_webgroup = get_any_webgroup_id(args.controller_ip,cid)
        # Write the gateway details to the output file as JSON
        with open('any_webgroup.json', 'w') as f:
            json.dump(any_webgroup, f, indent=1)

    resources = ["firewall","firewall_policy","firewall_tag","fqdn","fqdn_pass_through","fqdn_tag_rule"]
    for resource in resources:
        get_tf_resources(args.controller_ip, resource, cid)

    # Bundle all the files into a ZIP and delete the original
    other_files = ["gateway_details.json"]
    if args.any_web == True:
        other_files = other_files + ["any_webgroup.json"]
    files = ["{}.tf".format(x) for x in resources] + other_files
    zf = zipfile.ZipFile(args.output, mode="w")
    try:
        for file_name in files:
            # Add file to the zip file
            # first parameter file to zip, second filename in zip
            zf.write(file_name, file_name, compress_type=zipfile.ZIP_STORED)
            os.remove(file_name)

    except FileNotFoundError:
        print("An error occurred")
    finally:
        # Don't forget to close the file!
        zf.close()


if __name__ == '__main__':
    main()
