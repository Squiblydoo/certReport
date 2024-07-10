#!/usr/bin/python3
import requests
import json
import argparse
import os
from pathlib import Path

version = "2.0.2"

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
        api_key = os.getenv('VT_API_KEY')
        if api_key == None:
            raise KeyError
    except KeyError:
        print('''Please set your VirusTotal API key by running the doing the following:
        On Linux:
        echo "VT_API_KEY=your_api_key_here" >> ~/.bashrc
        source ~/.bashrc

        On Windows:
        setx VT_API_KEY "your_api_key"

        On MacOS:
        echo "export VT_API_KEY=your_api_key_here" >> ~/.zprofile
        source ~/.zprofile
        ''')
        exit()
    headers = {"accept": "application/json", "x-apikey": api_key}
    item_id = {"id": filehash}
    data_request = requests.get("https://www.virustotal.com/api/v3/files/" + filehash, headers=headers)
    try:
        data_request.raise_for_status()
    except requests.exceptions.HTTPError as e:
        if data_request.status_code == 401:
            print("API request was forbidden. Check to confirm your API key is correct.")
            exit()
        elif data_request.status_code == 404:
            print("The file hash was not found in VirusTotal's database.")
            exit()
        else:
            print("An error occurred while querying VirusTotal. Please try again later.")
            exit()
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
    signature_info = json_python_value.get("data", {}).get("attributes", {}).get("signature_info")
    if signature_info:
        signers = json_python_value["data"]["attributes"]["signature_info"]["signers"]
        signer_list = signers.split(";")
        subject_cn = signer_list[0]
        issuer_cn = signer_list[1]
        signer_details = json_python_value["data"]["attributes"]["signature_info"]["signers details"][0]
        cert_status = signer_details["status"]
        serial_number = signer_details["serial number"]
        thumbprint = signer_details["thumbprint"]
        valid_from = signer_details["valid from"]
        valid_to = signer_details["valid to"]

    stats = json_python_value["data"]["attributes"]["last_analysis_stats"]
    tags = json_python_value["data"]["attributes"]["tags"]
    tag_string = create_tag_string(tags)
    
    if signature_info:
        print("\n---------------------------------\nGreetings,\n "
            "We identified a malware signed with a " + issuer_cn + " certificate. \n"
            "The malware sample is available on VirusTotal here: https://www.virustotal.com/gui/file/" + filehash + "/detection\n\n"\
            "Here are the signature details:\n"\
                "Name: " + subject_cn + "\n"
                "Issuer: " + issuer_cn + "\n"
                "Serial Number: " + serial_number + "\n"
                "Thumbprint: " + thumbprint + "\n"
                "Certificate Status: " + cert_status + "\n"
                "Valid From: " + valid_from + "\n"
                "Valid Until: " + valid_to 
        )
    print(
            "The malware was tagged as a " + tag_string + "."
            "\n"
            "The malware was detected by " + str(stats["malicious"]) + " out of " + str(stats["harmless"] + stats["failure"] + stats["malicious"] + stats["suspicious"] + stats["undetected"]) + " antivirus engines."
            )
    popular_threat_classification = json_python_value.get("data", {}).get("attributes", {}).get("popular_threat_classification")
    if popular_threat_classification:
        popular_threat_category = json_python_value.get("data", {}).get("attributes", {}).get("popular_threat_classification", {}).get("popular_threat_category")
        if popular_threat_category:
            threat_type = json_python_value["data"]["attributes"]["popular_threat_classification"]["popular_threat_category"][0]
            print("The malware was classified as " + threat_type["value"] + " by " + str(threat_type["count"]) + " detection engines.")
        popular_threat_name = json_python_value.get("data", {}).get("attributes", {}).get("popular_threat_classification", {}).get("popular_threat_name")
        if popular_threat_name:
            threat_name = json_python_value["data"]["attributes"]["popular_threat_classification"]["popular_threat_name"]
            threat_name_list = []
            for threat in threat_name:
                threat_name_list.append(threat["value"] + " by " + str(threat["count"]) + " detection engines")
            threat_name_string = create_tag_string(threat_name_list)
            print("The file was flagged as " + threat_name_string)

    print("\nThis file was found during our investigation and had the following suspicious indicators:")
    # Additional evidence of malicious behavior can be found by HIGH IDS rules. Will consider other data later.
    high_ids_rules = []

    crowdsourced_ids_results = json_python_value.get("data", {}).get("attributes", {}).get("crowdsourced_ids_results")
    if crowdsourced_ids_results:
        for rule in json_python_value["data"]["attributes"]["crowdsourced_ids_results"]:
            if rule["alert_severity"] == "high":
                high_ids_rules.append(rule["rule_msg"])
        if  len(high_ids_rules) > 0:
            print(" - The file triggered the following high IDS rules: " )
            for rule in high_ids_rules:
                print("   - " + rule)
    if signature_info:
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


def main():
    parser = argparse.ArgumentParser(description = "Pull data pertaining to filehash by specifying hash associated with the malware and choosing a provider (defaults to MalwareBazaar).")
    parser.add_argument("-#","--hash", help="Specify hash of file to query.")
    parser.add_argument("-s", "--service", default="malwarebazaar", choices=["malwarebazaar", "VT", "virustotal"],
                        help="Select the service to query (default: malwarebazaar).")
    parser.add_argument('--version', action='version', version='%(prog)s ' + version)
    args = parser.parse_args()

    
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
