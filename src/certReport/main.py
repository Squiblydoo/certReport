#!/usr/bin/python3
import requests
import json
import argparse
import os
import sqlite3
import certReport.databaseFunctions.databaseManager as db_manager
from pathlib import Path

version = "3.1.4"
db, cursor = db_manager.connect_to_db()


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
            print("An error occurred while querying VirusTotal: " + str(e))
            exit()
    json_python_value = data_request.json()
    return json_python_value

def get_issuer_simple_name(issuer_cn):
    if "SSL" in issuer_cn:
        return "SSL.com"
    elif "Certum" in issuer_cn:
        return "Certum"
    elif "DigiCert" in issuer_cn:
        return "DigiCert"
    elif "GlobalSign" in issuer_cn:
        return "GlobalSign"
    elif "Sectigo" in issuer_cn:
        return "Sectigo"
    elif "Entrust" in issuer_cn:
        return "Entrust"
    else:
        return "Unknown"

def print_reporting_instructions(issuer_cn):
    print("")
    print("Please let us know if you have any questions.")
    print("------------------------")
    print('''Send the above message to the certificate provider. ''')

    if "SSL" in issuer_cn:
        print("This report should be sent to SSL.com: https://ssl.com/revoke")
    elif "Certum" in issuer_cn:
        print("This report should be sent to Certum PL: https://problemreport.certum.pl/")
    elif "DigiCert" in issuer_cn:
        print("This report should be sent to DigiCert: Revoke@digicert.com")
    elif "GlobalSign" in issuer_cn:
        print("This report should be sent to GlobalSign: report-abuse@globalsign.com")
    elif "Sectigo" in issuer_cn:
        print("This report should be sent to Sectigo: signedmalwarealert@sectigo.com")
    elif "Entrust" in issuer_cn:
        print("This report should be sent to Entrust: https://www.entrust.com/support/certificate-solutions/report-a-problem#form-block")
    else:
        print("Assuming this is a valid certificate. Search the provider's website for the reporting email.")

def process_virustotal_data(json_python_value, filehash, user_supplied_tag, min_report):
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

        issuer_simple_name = get_issuer_simple_name(issuer_cn)
        if issuer_simple_name == "Certum":
            min_report = True # Certum reports are always thin reports due to report length requirements.
        
        if min_report:
            if signature_info:
                print("\n---------------------------------\nGreetings,\n "
                    "The following malware is signed by a " + issuer_simple_name + " subscriber: https://www.virustotal.com/gui/file/" + filehash + "/detection\n\n"\
                        "Name: " + subject_cn + "\n"
                        "Issuer: " + issuer_cn + "\n"
                        "Serial Number: " + serial_number + "\n"
                        "Thumbprint: " + thumbprint + "\n"
                        "Status: " + cert_status + "\n"
                )

        else:    
            if signature_info:
                print("\n---------------------------------\nGreetings,\n "
                    "We identified a malware signed with a" + issuer_cn + " certificate. \n"
                    "The malware sample is available on VirusTotal here: https://www.virustotal.com/gui/file/" + filehash + "/detection\n\n"\
                    "Here are the signature details:\n"\
                        "Name: " + subject_cn + "\n"
                        "Issuer: " + issuer_cn + "\n"
                        "Serial Number: " + serial_number + "\n"
                        "Thumbprint: " + thumbprint + "\n"
                        "Certificate Status: " + cert_status + "\n"
                        "Valid From: " + valid_from + "\n"
                        "Valid Until: " + valid_to + "\n"                    
                )
    if not signature_info:
        print("This file is not signed. Only printing report.\n---------------------------------")


    stats = json_python_value["data"]["attributes"]["last_analysis_stats"]
    tags = json_python_value["data"]["attributes"]["tags"]
    tag_string = create_tag_string(tags)

            
    if user_supplied_tag:
        print("This malware is known as " + user_supplied_tag + ".\n")
        tag_string += ", " + user_supplied_tag

    print(
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

    
    # Additional evidence of malicious behavior can be found by HIGH IDS rules. Will consider other data later.
    high_ids_rules = []
    critical_high_sigma_rules = []

    crowdsourced_ids_results = json_python_value.get("data", {}).get("attributes", {}).get("crowdsourced_ids_results")
    sigma_analysis_results = json_python_value.get("data", {}).get("attributes", {}).get("sigma_analysis_results")
    crowdsourced_yara_results = json_python_value.get("data", {}).get("attributes", {}).get("crowdsourced_yara_results")
    malware_config = json_python_value.get("data", {}).get("attributes", {}).get("malware_config")
    
    indicator_array = []
    if crowdsourced_ids_results:
        for rule in json_python_value["data"]["attributes"]["crowdsourced_ids_results"]:
            if rule["alert_severity"] == "high":
                high_ids_rules.append(rule["rule_msg"])
        if  len(high_ids_rules) > 0:
            indicator_array.append(" - The file triggered the following high IDS rules: " )
            for rule in high_ids_rules:
                indicator_array.append("   - " + rule)

    if sigma_analysis_results:
        for rule in json_python_value["data"]["attributes"]["sigma_analysis_results"]:
            if rule["rule_level"] in ("critical", "high"):
                critical_high_sigma_rules.append(rule["rule_title"])
        if  len(critical_high_sigma_rules) > 0:
            indicator_array.append(" - The file triggered the following critical or high Sigma rules: " )
            for rule in critical_high_sigma_rules:
                indicator_array.append("   - " + rule)

    if crowdsourced_yara_results:
        indicator_array.append(" - The file triggered the following YARA rules: " )
        for rule in json_python_value["data"]["attributes"]["crowdsourced_yara_results"]:
            indicator_array.append("   - " + rule["rule_name"] + " from source " + rule["source"])

    if malware_config:
        indicator_array.append(" - VirusTotal extracted configurations for the following malware families: " )
        for family in json_python_value["data"]["attributes"]["malware_config"]["families"]:
            indicator_array.append("   - " + family["family"])
    if indicator_array:
        print("\nThis file was found during our investigation and had the following suspicious indicators:")
        for indicator in indicator_array:
            print(indicator)

    if signature_info:
        issuer_simple_name = get_issuer_simple_name(issuer_cn)
        db_manager.insert_into_db(db, cursor, filehash, user_supplied_tag, subject_cn, issuer_cn, issuer_simple_name, serial_number, thumbprint, valid_from, valid_to, tag_string, "VirusTotal")
        if user_supplied_tag:
            data = db_manager.summarize_entries_by_tag(cursor, user_supplied_tag)
            combined_non_matching_values = 0

            for entry in data:
                if entry[0] == issuer_simple_name:
                    if entry[1] > 1:
                        print(f"\nWe have reported this same malware to {issuer_simple_name} {entry[1]} times. ", end='')
                else:
                    combined_non_matching_values += entry[1]

            if combined_non_matching_values > 0:
                print(f"We have reported the malware to other providers {combined_non_matching_values} times.")
        
    if signature_info:
        print_reporting_instructions(issuer_cn)
        

def process_malwarebazaar_data(json_python_value, filehash, user_supplied_tag, min_report):
    if json_python_value["data"][0]["code_sign"]:
        subject_cn = json_python_value["data"][0]["code_sign"][0]["subject_cn"]
        issuer_cn = json_python_value["data"][0]["code_sign"][0]["issuer_cn"]
        serial_number = json_python_value["data"][0]["code_sign"][0]["serial_number"]
        thumbprint = json_python_value["data"][0]["code_sign"][0]["thumbprint"]
        valid_from = json_python_value["data"][0]["code_sign"][0]["valid_from"]
        valid_until = json_python_value["data"][0]["code_sign"][0]["valid_to"]

        tags = json_python_value["data"][0]["tags"]
        tag_string = create_tag_string(tags)

        issuer_simple_name = get_issuer_simple_name(issuer_cn)
        if issuer_simple_name == "Certum":
            min_report = True # Certum reports are always thin reports due to report length requirements.

        if min_report:
            print("\n---------------------------------\nGreetings,\n "
                "We identified a malware signed with a " + issuer_cn + " certificate: https://bazaar.abuse.ch/sample/" + filehash + "\n"\
                "Here are the signature details:\n"\
                    "Name: " + subject_cn + "\n"
                    "Issuer: " + issuer_cn + "\n"
                    "Serial Number: " + serial_number + "\n"
                    "SHA256 Thumbprint: " + thumbprint + "\n"
                    "\n"
                    )
        else:
            print("\n---------------------------------\nGreetings,\n "
                "We identified a malware signed with a " + issuer_cn + " certificate. \n" 
                "The malware sample is available on MalwareBazaar here: https://bazaar.abuse.ch/sample/" + filehash + "\n"\
                "Here are the signature details:\n"\
                    "Name: " + subject_cn + "\n"
                    "Issuer: " + issuer_cn + "\n"
                    "Serial Number: " + serial_number + "\n"
                    "SHA256 Thumbprint: " + thumbprint + "\n"
                    "Valid From: " + valid_from + "\n"
                    "Valid Until: " + valid_until + "\n"
                    "The malware was tagged as " + tag_string + ".\n"
                    "\n"
                    )
            if user_supplied_tag:
                print("This malware is known as " + user_supplied_tag + ".\n")
                tag_string += ", " + user_supplied_tag
            print(
                    "MalwareBazaar submitted the file to multiple public sandboxes, the links to the sandbox results are below:\n"
                    "Sandbox\t / Malware Family\t /  Verdict\t / Analysis URL"
                    )
    
    vendor_intel_dict = json_python_value["data"][0]["vendor_intel"]
    for key, value in vendor_intel_dict.items():
        if key == 'ANY.RUN':
            print(f"{key} \t {value[0]['malware_family']}\t {value[0]['verdict']}\t {value[0]['analysis_url']}")
        elif key == 'Triage':
            print(f"{key} \t {value['malware_family']} \t {value['score']} / 10\t {value['link']} ")
        elif key == 'Intezer':
            print(f"{key} \t {value['family_name']} \t {value['verdict']} \t {value['analysis_url']} ")
        elif key == 'VMRay':
            print(f"{key} \t {value['malware_family']} \t {value['verdict']} \t {value['report_link']} ")
    
    if json_python_value["data"][0]["code_sign"]:
        db_manager.insert_into_db(db, cursor, filehash, user_supplied_tag, subject_cn, issuer_cn, issuer_simple_name, serial_number, thumbprint, valid_from, valid_until, tag_string, "MalwareBazaar")
        if user_supplied_tag:
            data = db_manager.summarize_entries_by_tag(cursor, user_supplied_tag)
            combined_non_matching_values = 0

            for entry in data:
                if entry[0] == issuer_simple_name:
                    if entry[1] > 1:
                        print(f"\nWe have reported this same malware to {issuer_simple_name} {entry[1]} times. ", end='')
                else:
                    combined_non_matching_values += entry[1]

            if combined_non_matching_values > 0:
                print(f"We have reported the malware to other providers {combined_non_matching_values} times.")

        print_reporting_instructions(issuer_cn)
        


def main():
    parser = argparse.ArgumentParser(description = "Pull data pertaining to filehash by specifying hash associated with the malware and choosing a provider (defaults to MalwareBazaar).")
    parser.add_argument("-#","--hash", help="Specify hash of file to query.")
    parser.add_argument("-s", "--service", default="malwarebazaar", choices=["MB", "malwarebazaar", "VT", "virustotal"],
                        help="Select the service to query (default: malwarebazaar).")
    parser.add_argument('--version', action='version', version='%(prog)s ' + version)
    parser.add_argument('-t', '--tag', help="Tag the malware as a specific family")
    parser.add_argument('-m', '--min', help="Prints a thin report with only the most important information", default=False ,action="store_true")
    args = parser.parse_args()

    if not args.hash:
        parser.error("the following arguments are required: --hash")

    if args.service == "virustotal" or args.service == "VT":
        json_python_value = query_virustotal(args.hash)
        process_virustotal_data(json_python_value, args.hash, args.tag, args.min)
    else:  # Default to MalwareBazaar
        json_python_value = query_malwarebazaar(args.hash)
        if json_python_value["query_status"] == "hash_not_found":
            print("The hash was not found in MalwareBazaar's database.")
            exit()
        process_malwarebazaar_data(json_python_value, args.hash, args.tag, args.min)

    db_manager.close_db(db)
            
if __name__=="__main__":
    main()
