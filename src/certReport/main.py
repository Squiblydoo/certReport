#!/usr/bin/python3
import requests
import json
import argparse
import os
from pathlib import Path
from dotenv import load_dotenv
load_dotenv()

version = "2.0"

def create_tag_string(tags):
    if len(tags) == 0:
        return ""
    elif len(tags) == 1:
        return tags[0]
    else:
        tag_string = ", ".join(tags[:-1])
        tag_string += " and " + tags[-1]
        return tag_string

def query_malwarebazaar(filehash):
    query = {"query": "post-data", "query": "get_info", "hash": filehash}
    data_request = requests.post("https://mb-api.abuse.ch/api/v1/", data=query)
    data_request.raise_for_status()
    json_string = data_request.text
    json_python_value = json.loads(json_string)
    return json_python_value

def query_virustotal(filehash):
    try:
        api_key = os.environ['VT_API_KEY']
    except KeyError:
        print("Please set your VirusTotal API key by running the script with the argument '--setup <API-KEY>.")
        exit()
    headers = {"accept": "application/json", "x-apikey": api_key}
    item_id = {"id": filehash}
    data_request = requests.get("https://www.virustotal.com/api/v3/files/" + filehash, headers=headers)
    data_request.raise_for_status()
    json_python_value = data_request.json()
    return json_python_value

def print_reporting_instructions(issuer_cn):
    print("")
    print("Please let us know if you have any questions.")
    print("------------------------")
    print('''Send the above message to the certificate provider. ''')
    if "SSL" in issuer_cn:
        print("This report should be sent to SSL.com: https://ssl.com/revoke")
    elif "Certum" in issuer_cn:
        print("This report should be sent to Certum PL: https://problemreport.certum.pl/")
    elif "Digicert" in issuer_cn:
        print("This report should be sent to Digicert: Revoke@digicert.com")
    elif "GlobalSign" in issuer_cn:
        print("This report should be sent to GlobalSign: report-abuse@globalsign.com")
    elif "Sectigo" in issuer_cn:
        print("This report should be sent to Sectigo: signedmalwarealert@sectigo.com")
    elif "Entrust" in issuer_cn:
        print("This report should be sent to Entrust: ecs.support@entrust.com")
    else:
        print("Assuming this is a valid certificate. Search the provider's website for the reporting email.")

def process_virustotal_data(json_python_value, filehash):
    signers = json_python_value["data"]["attributes"]["signature_info"]["signers"]
    signer_list = signers.split(";")
    subject_cn = signer_list[0]
    issuer_cn = signer_list[1]
    x509_details = json_python_value["data"]["attributes"]["signature_info"]["x509"][0]
    serial_number = x509_details["serial number"]
    thumbprint = x509_details["thumbprint"]
    valid_from = x509_details["valid from"]
    valid_to = x509_details["valid to"]

    stats = json_python_value["data"]["attributes"]["last_analysis_stats"]
    tags = json_python_value["data"]["attributes"]["tags"]
    tag_string = create_tag_string(tags)
    
    print("\n---------------------------------\nGreetings,\n "
        "We identified a malware signed with a " + issuer_cn + " certificate. \n"
        "The malware sample is available on VirusTotal here: https://www.virustotal.com/gui/file/" + filehash + "/detection\n\n"\
        "Here are the signature details:\n"\
            "Name: " + subject_cn + "\n"
            "Issuer: " + issuer_cn + "\n"
            "Serial Number: " + serial_number + "\n"
            "Thumbprint: " + thumbprint + "\n"
            "Valid From: " + valid_from + "\n"
            "Valid Until: " + valid_to +
            "\n\n"
            "The malware was tagged as a " + tag_string + "."
            "\n"
            "The malware was detected by " + str(stats["malicious"]) + " out of " + str(stats["harmless"] + stats["failure"] + stats["malicious"] + stats["suspicious"] + stats["undetected"]) + " antivirus engines."
            )
    if json_python_value["data"]["attributes"]["popular_threat_classification"]:
        threat_type = json_python_value["data"]["attributes"]["popular_threat_classification"]["popular_threat_category"][0]
        print("The malware was classified as " + threat_type["value"] + " by " + str(threat_type["count"]) + " detection engines.")
        threat_name = json_python_value["data"]["attributes"]["popular_threat_classification"]["popular_threat_name"]
        threat_name_list = []
        for threat in threat_name:
            threat_name_list.append(threat["value"] + " by " + str(threat["count"]) + " detection engines")
        threat_name_string = create_tag_string(threat_name_list)
        print("The file was flagged as " + threat_name_string)

    print("\nThis file was found during our investigation and had the following suspicious indicators:")
    # Additional evidence of malicious behavior can be found by HIGH IDS rules. Will consider other data later.
    high_ids_rules = []
    if json_python_value["data"]["attributes"]["crowdsourced_ids_results"]:
        for rule in json_python_value["data"]["attributes"]["crowdsourced_ids_results"]:
            if rule["alert_severity"] == "high":
                high_ids_rules.append(rule["rule_msg"])
    high_ids_rules_list = create_tag_string(high_ids_rules)
    if  len(high_ids_rules) > 0:
        print(" - The file triggered the following high IDS rules: " + high_ids_rules_list)

    print_reporting_instructions(issuer_cn)

def process_malwarebazaar_data(json_python_value, filehash):
    subject_cn = json_python_value["data"][0]["code_sign"][0]["subject_cn"]
    issuer_cn = json_python_value["data"][0]["code_sign"][0]["issuer_cn"]
    serial_number = json_python_value["data"][0]["code_sign"][0]["serial_number"]
    thumbprint = json_python_value["data"][0]["code_sign"][0]["thumbprint"]
    valid_from = json_python_value["data"][0]["code_sign"][0]["valid_from"]
    valid_until = json_python_value["data"][0]["code_sign"][0]["valid_to"]

    tags = json_python_value["data"][0]["tags"]
    tag_string = create_tag_string(tags)
    vendor_intel_dict = json_python_value["data"][0]["vendor_intel"]

    print("\n---------------------------------\nGreetings,\n "
        "We identified a malware signed with a " + issuer_cn + " certificate. \n" 
        "The malware sample is available on MalwareBazaar here: https://bazaar.abuse.ch/sample/" + filehash + "\n"\
        "Here are the signature details:\n"\
            "Name: " + subject_cn + "\n"
            "Issuer: " + issuer_cn + "\n"
            "Serial Number: " + serial_number + "\n"
            "SHA256 Thumbprint: " + thumbprint + "\n"
            "Valid From: " + valid_from + "\n"
            "Valid Until: " + valid_until +
            "\n"
            "The malware was tagged as " + tag_string + "."
            "\n"
            "MalwareBazaar submitted the file to multiple public sandboxes, the links to the sandbox results are below:\n"
            "Sandbox\t / Malware Family\t /  Verdict\t / Analysis URL"
            )
            
    for key, value in vendor_intel_dict.items():
        if key == 'ANY.RUN':
            print(f"{key} \t {value[0]['malware_family']}\t {value[0]['verdict']}\t {value[0]['analysis_url']}")
        elif key == 'Triage':
            print(f"{key} \t {value['malware_family']} \t {value['score']} / 10\t {value['link']} ")
        elif key == 'Intezer':
            print(f"{key} \t {value['family_name']} \t {value['verdict']} \t {value['analysis_url']} ")
        elif key == 'VMRay':
            print(f"{key} \t {value['malware_family']} \t {value['verdict']} \t {value['report_link']} ")

    print_reporting_instructions(issuer_cn)

def create_or_update_env_file(api_key):
    with open('.env', 'w') as env_file:
        env_file.write(f'VT_API_KEY={api_key}\n')
    print("API key has been saved to .env file.")

def main():
    parser = argparse.ArgumentParser(description = "Pull data pertaining to filehash by specifying hash associated with the malware and choosing a provider (defaults to MalwareBazaar).")
    parser.add_argument("-#","--hash", help="Specify hash of file to query.")
    parser.add_argument("-s", "--service", default="malwarebazaar", choices=["malwarebazaar", "VT", "virustotal"],
                        help="Select the service to query (default: malwarebazaar).")
    parser.add_argument('--setup', metavar='API_KEY', type=str, help='Setup your API key by passing the API key as an argument.')
    parser.add_argument('--version', action='version', version='%(prog)s ' + version)

    args = parser.parse_args()

    if args.setup:
        create_or_update_env_file(args.setup)
        exit()
    
    if not args.hash:
        parser.error("the following arguments are required: --hash")

    if args.service == "virustotal" or args.service == "VT":
        json_python_value = query_virustotal(args.hash)
        process_virustotal_data(json_python_value, args.hash)
    else:  # Default to MalwareBazaar
        json_python_value = query_malwarebazaar(args.hash)
        process_malwarebazaar_data(json_python_value, args.hash)
            
if __name__=="__main__":
    main()
