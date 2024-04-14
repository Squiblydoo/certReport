#!/usr/bin/python

import requests
import json
import argparse
import os
from pathlib import Path

def create_tag_string(tags):
    if len(tags) == 0:
        return ""
    elif len(tags) == 1:
        return tags[0]
    else:
        tag_string = ", ".join(tags[:-1])
        tag_string += " and " + tags[-1]
        return tag_string

def main():
    parser = argparse.ArgumentParser(description = "Pull data pertaining to filehash from MalwareBazzar by specifying hash associated with the malware.")
    parser.add_argument("hash", help="Specify hash of file to query.")
    args = parser.parse_args()
    #Make request for Data
    query = {"query": "post-data", "query": "get_info", "hash": args.hash}
    data_request = requests.post("https://mb-api.abuse.ch/api/v1/", data=query)

    data_request.raise_for_status()
    json_string = data_request.text
    json_python_value = json.loads(json_string)
    if json_python_value["data"][0]["code_sign"]:
        subject_cn = json_python_value["data"][0]["code_sign"][0]["subject_cn"]
        issuer_cn = json_python_value["data"][0]["code_sign"][0]["issuer_cn"]
        serial_number = json_python_value["data"][0]["code_sign"][0]["serial_number"]
        thumbprint = json_python_value["data"][0]["code_sign"][0]["thumbprint"]

        tags = json_python_value["data"][0]["tags"]
        tag_string = create_tag_string(tags)
        vendor_intel_dict = json_python_value["data"][0]["vendor_intel"]
    
        print("\n---------------------------------\nGreetings,\n "
            "We identified a malware signed with an " + issuer_cn + " certificate. \n" 
            "The malware sample is available on MalwareBazaar here: https://bazaar.abuse.ch/sample/" + args.hash + "\n"\
            "Here are the signature details:\n"\
                "Name: " + subject_cn + "\n"
                "Issuer: " + issuer_cn + "\n"
                "Serial Number: " + serial_number + "\n"
                "SHA256 Thumbprint: " + thumbprint + "\n"
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
        
        print("")
        print("Please let us know if you have any questions.")
        print("------------------------")
        print('''Send the above message to the certificate provider. ''')
        if "SSL" in issuer_cn:
            print("This report should be sent to SSL.com: https://ssl.com/revoke")
        elif "Certum" in issuer_cn:
            print("This report should be sent to Certum PL: ccp@certum.pl")
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


        
    
            
if __name__=="__main__":
    main()
