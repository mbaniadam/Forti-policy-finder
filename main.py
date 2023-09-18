import os
import sys
import ipaddress
import csv
import urllib3
import requests
import yaml


# import logging
# logging.basicConfig(filename='netmiko_global.log', level=logging.DEBUG)
# logger = logging.getLogger("netmiko")

os.chdir(os.path.dirname(os.path.abspath(sys.argv[0])))
path = os.getcwd()
print(path)


def read_yaml(yml_path="inventory.yml"):
    """
    Read and load content from a YAML file.

    This function reads the content from a specified YAML file and returns
    the loaded content as a Python dictionary.

    Args:
        path (str, optional): The path to the YAML file. Defaults to "inventory.yml".

    Returns:
        dict: A dictionary containing the loaded content from the YAML file.
    """
    with open(yml_path, encoding="utf-8") as yaml_file:
        yaml_content = yaml.safe_load(yaml_file.read())
        # print(yaml_content)
    return yaml_content


def is_host_in_subnet(subnet, input_ip):
    """
    Check if an IP address belongs to a given subnet.

    This function takes a subnet and an IP address as input and checks if
    the IP address is within the specified subnet.

    Args:
        subnet (str): The subnet in CIDR notation.
        ip (str): The IP address to check.

    Returns:
        str: The subnet if the IP address belongs to it, otherwise None.
    """
    try:
        if "0.0.0.0/0" not in subnet:
            subnet_network = ipaddress.IPv4Network(subnet, strict=False)
            input_ip = ipaddress.IPv4Network(input_ip, strict=False)
            if input_ip.subnet_of(subnet_network):
                return str(subnet)
        # else:
        #     print(f"{subnet} not allowed!")
        return None
    except ValueError:
        print(ValueError)


def valiadate_ip(input_ip):
    """
    Validate an IP address.

    This function takes an IP address as input and checks if it's a valid IP address.
    It also checks if the IP address is not APIPA or or "0.0.0.0/0".

    Args:
        ip (str): The IP address to validate.

    Returns:
        str: The validated IP address if it's valid, otherwise None.
    """
    try:
        print(f"-------------------------\nChecking {input_ip} ...")
        if input_ip == ("169.254.0.0", "0.0.0.0/0"):
            return None
        ip_interface = ipaddress.ip_interface(input_ip)
        # ip_cidr = ip_interface.with_netmask.split('/')[1]
        # pref_len = ip_interface.with_prefixlen.split('/')[1]
        if ip_interface:
            print(" IP:", input_ip, "is valid.")
            return str(ip_interface)
        return None
    except ValueError:
        print(" IP address is not valid!")


def make_api_request(url, method, headers=None, data=None):
    """
    Make an HTTP API request.

    This function sends an HTTP request to the given URL using the specified method.
    It allows sending optional headers and data along with the request.

    Args:
        url (str): The URL to send the request to.
        method (str): The HTTP method to use ('GET', 'POST', 'DELETE').
        headers (dict, optional): Optional headers to include in the request.
        data (dict or str, optional): Data to include in the request (for 'POST' and 'DELETE' methods).

    Returns:
        requests.Response or None: The response object if the request is successful and
        the status code is not 500, 404, or 403. None is returned in case of an error.

    Raises:
        ValueError: If an invalid HTTP method is provided.

    Note:
        This function suppresses SSL verification (verify=False) for simplicity.
        Use with caution in production environments.
    """
    try:
        if method == 'GET':
            response = requests.get(
                url, verify=False, headers=headers, timeout=10)
        elif method == 'POST':
            response = requests.post(
                url, verify=False, headers=headers, data=data, timeout=10)
        elif method == 'DELETE':
            response = requests.delete(
                url, verify=False, headers=headers, data=data, timeout=10)
        else:
            raise ValueError("Invalid HTTP method")

        if response.status_code in (500, 404, 403):
            return response

        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as http_error:
        print(f"An error occurred: {http_error}")
        return None


def forti_policy_finder(host, ip_list_validated, result_file):
    """
    Find object dependencies via Fortinet FortiGate API.

    This function takes a host configuration, a list of validated IP addresses,
    and a result file for generating the output. It analyzes network policies
    on a FortiGate device, identifying address dependencies, address groups,
    interfaces, and policies related to the given IP addresses.

    Parameters:
    host (dict): A dictionary containing host configuration details including
                 'host', 'port', and 'token' for API access.
    ip_list_validated (list): A list of validated IP addresses (with CIDR notation)
                             to analyze for dependencies.
    result_file (CSV writer): A CSV writer object to write the results.

    Returns:
    None: This function generates output in the provided result_file.

    Raises:
    SystemExit: If there's a RequestException during API calls to the FortiGate device.

    """
    print("**************************** Find policies via API ****************************")
    print(">>> Looking in ", host["host"])
    urllib3.disable_warnings()

    device_ip = host["host"]
    port = host["port"]
    access_token = host["token"]
    headers = {"Authorization": "Bearer " + access_token, }
    vdom = host.get("vdom", "")
    and_host_vdom = f'&vdom={vdom}' if vdom else ""
    host_vdom = f'?vdom={vdom}' if vdom else ""
    # Write header for device in csv file
    result_file.writerow(["------- Device: ",host["host"]])
    # Get all address
    url_all_addr = f'https://{device_ip}:{port}/api/v2/cmdb/firewall/address/?format=name|subnet|type&filter=type==ipmask{and_host_vdom}'
    response_all_addr_check = make_api_request(
        url_all_addr, "GET", headers).json()["results"]
    # get interfaces to find vlan of ip address
    url_all_interfaces = f'https://{device_ip}:{port}/api/v2/cmdb/system/interface/?format=ip|name{and_host_vdom}'
    response_interface_check = make_api_request(
        url_all_interfaces, "GET", headers).json()["results"]
    all_interfaces = list(
        map(lambda x: {**x, "ip": x["ip"].replace(' ', '/')}, response_interface_check))
    # Find zones
    url_all_zones = f'https://{device_ip}:{port}/api/v2/cmdb/system/zone/?format=name|interface{and_host_vdom}'
    response_zone_check = make_api_request(
        url_all_zones, "GET", headers).json()["results"]
    # Find subnets and replace space with slash in subnet value for use in subnet_of() function
    all_subnet = list(map(lambda x: {
        **x, "subnet": x["subnet"].replace(' ', '/')}, response_all_addr_check))
    # Get all groups
    url_addrgrp = f'https://{device_ip}:{port}/api/v2/cmdb/firewall/addrgrp/?format=name|member{and_host_vdom}'
    response_grp_check = make_api_request(
        url_addrgrp, "GET", headers).json()["results"]
    # Get all policies
    url_all_policy = f'https://{device_ip}:{port}/api/v2/cmdb/firewall/policy/{host_vdom}'
    result_url_all_policy = make_api_request(
        url_all_policy, "GET", headers).json()["results"]
    for ip_with_cidr in ip_list_validated:
        print("------- Address:", ip_with_cidr)
        result_file.writerow(["------- Address:", ip_with_cidr])
        ip_without_cidr = ip_with_cidr.split('/')[0]
        founded_grp_list = []
        subnet_check = list(
            filter(lambda x, ip_addr_l=ip_with_cidr: is_host_in_subnet(x["subnet"], ip_addr_l), all_subnet))
        filtered_addresses = list(filter(lambda x, ip_addr_l=ip_without_cidr: x["subnet"].split()[
            0] == ip_addr_l, response_all_addr_check))
        if filtered_addresses:
            address_name = filtered_addresses[0]["name"]
        else:
            address_name = None
        # Count all groups and check address in every group
        for res_group in response_grp_check:
            for member in res_group["member"]:
                if res_group["name"] not in founded_grp_list and member["name"] == address_name:
                    founded_grp_list.append(res_group["name"])
                # founded_grp_list.append(subnet['name'] for subnet in subnet_check if subnet['name'] == member["name"])
                for subnet in subnet_check:
                    if res_group["name"] not in founded_grp_list and subnet['name'] == member["name"]:
                        founded_grp_list.append(res_group["name"])
        print("------- List of groups containing ip:", founded_grp_list)
        result_file.writerow(["------- List of groups containing ip:", founded_grp_list])
        # Add matched subnet name with the ip address to the list
        for subnet in subnet_check:
            founded_grp_list.append(subnet['name'])
        # find vlan of address
        interface_check = list(
            map(lambda x, ip_addr_l=ip_with_cidr: [x["name"], x["ip"]] if
                is_host_in_subnet(x["ip"], ip_addr_l) else False, all_interfaces))
        filtered_interfaces_list = list(filter(None, interface_check))
        filtered_zone = "unknown-zone"
        filtered_interface = "unknown-int"
        if filtered_interfaces_list:
            filtered_interface = filtered_interfaces_list[0][0]
            zones_with_interface = list(
                map(
                    lambda int_name: int_name["name"],
                    filter(
                        lambda int_name: any(
                            filtered_interface in zone["interface-name"]
                            for zone in int_name["interface"]
                        ),
                        response_zone_check,
                    ),
                )
            )
            if zones_with_interface:
                filtered_zone = zones_with_interface[0]
        # print(founded_grp_list)
        # Check source and destination address and group in policy
        for pid in result_url_all_policy:
            pid_policyid = pid["policyid"]
            pid_srcaddr = list(map(lambda x: x["name"], pid["srcaddr"]))
            pid_dstaddr = list(map(lambda x: x["name"], pid["dstaddr"]))
            pid_schedule = pid["schedule"]
            pid_action = pid["action"]
            pid_status = pid["status"]
            pid_services = list(map(lambda x: x['name'], pid["service"]))
            pid_srcint = list(map(lambda x: x["name"], pid["srcintf"]))
            pid_dstint = list(map(lambda x: x["name"], pid["dstintf"]))
            srcint_check = filtered_zone in pid_srcint or filtered_interface in pid_srcint
            if pid_status == "enable":
                for grp in founded_grp_list:
                    srcaddr_check = grp in pid_srcaddr
                    dstaddr_check = grp in pid_dstaddr
                    if grp == "all" and pid_action == "deny":
                        pass
                    elif srcaddr_check and srcint_check:
                        result_file.writerow([
                            pid_policyid, f'{ip_without_cidr} or Group', pid_dstaddr, pid_srcint,
                            pid_dstint, pid_services, pid_schedule, pid_action
                        ])
                    elif dstaddr_check:
                        result_file.writerow([
                            pid_policyid, pid_srcaddr, f'{ip_without_cidr} or Group', pid_srcint,
                            pid_dstint, pid_services, pid_schedule, pid_action
                        ])

    print(
        f"\n    Finished! you can see result in:\
                {os.path.join(path, 'Dependencies_Result.csv')}")


if __name__ == "__main__":
    EXIT_CODE = "n"
    while EXIT_CODE != "y":
        try:
            parsed_yaml = read_yaml()
            with open("IP_LIST.csv", encoding="utf-8") as file,\
                    open("Dependencies_Result.csv", "w",
                         newline='', encoding="utf-8") as csv_result:
                result_file = csv.writer(csv_result)
                result_file.writerow(
                    ["policyid", "srcaddr", "dstaddr", "srcintf", "dstintf", "services", "schedule", "action"])
                csvreader = csv.reader(file)
                ip_list_validated = []
                for IP_line in csvreader:
                    ip_with_cidr = IP_line[0]
                    if "/" not in ip_with_cidr:
                        ip_with_cidr = ip_with_cidr+"/32"
                    ip_validated = valiadate_ip(ip_with_cidr)
                    if ip_validated:
                        ip_list_validated.append(ip_with_cidr)
                print(
                    "----------------------------------"
                    "\nIP validation has finished process!\n"
                    "----------------------------------"
                )
                if ip_list_validated:
                    for host in parsed_yaml["hosts"]:
                        device_type = host["device_type"]
                        if device_type == "fortinet":
                            forti_policy_finder(host, ip_list_validated,result_file)
                        else:
                            print(f"Unsupported device type: {device_type}")
                else:
                    print("No valid IP found!")
        except FileNotFoundError as file_error:
            print("File not found error:", file_error)
        except csv.Error as csv_error:
            print("CSV error:", csv_error)
        except KeyError as key_error:
            print("Key error:", key_error)
        except Exception as exception_error:
            print("An error occurred:", exception_error)

        EXIT_CODE = str(input("\n Finished! Exit?! (y/n) ")
                        or "y").strip().lower()
        if EXIT_CODE in ("y", "yes"):
            os.sys.exit(0)
