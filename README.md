# CertReport

This tool is intended to reduce the load of effort required to report authenticode certificates. It is intended to take the smallest amount of effort from the reporter, but provide the certificate authority with most the information they need to make a decision. When possible, it is recommended to augment the report with your own findings to help the certificate provider know what suspicious indicators you found.

As of version 2, we have added support to use VirusTotal API. In order to allow for VirusTotal API, we have added additional functions. 
The default behavior of cert report is to query MalwareBazaar, which does not require an API key.

In version 3, we have added a SQLite database which stores information about the reports. This can be used for personal reference but also augments the report. See information in the database section below for more information!

## Installing
Use pip! `pip install certReport` or `pip3 install certReport`

## Usage

**Note: In version 2, it is required to provide the `--hash` (or `-#`) switch**
 Here is an example:
Calling the script and passing in a SHA256 like this:<br>
`certReport --hash 89dc50024836f9ad406504a3b7445d284e97ec5dafdd8f2741f496cac84ccda9`

Will print the following information to the console:

```
---------------------------------
Greetings,
 We identified a malware signed with a SSL.com EV Code Signing Intermediate CA RSA R3 certificate. 
The malware sample is available on MalwareBazaar here: https://bazaar.abuse.ch/sample/89dc50024836f9ad406504a3b7445d284e97ec5dafdd8f2741f496cac84ccda9
Here are the signature details:
Name: A.P.Hernandez Consulting s.r.o.
Issuer: SSL.com EV Code Signing Intermediate CA RSA R3
Serial Number: 2941d5f8758501f9dbc4ba158058c3b5
SHA256 Thumbprint: a982917ba6de9588f0f7ed554223d292524e832c1621acae9ad11c0573df54a5
Valid From: 2024-01-25T16:51:40Z
Valid Until: 2025-01-24T16:51:40Z

The malware was tagged as exe, Pikabot and signed.

MalwareBazaar submitted the file to multiple public sandboxes, the links to the sandbox results are below:
Sandbox	 / Malware Family	 /  Verdict	 / Analysis URL
Intezer 	 None 	 unknown 	 https://analyze.intezer.com/analyses/c4915ef4-198f-4aba-81ed-81b29cd4dce6?utm_source=MalwareBazaar 
Triage 	 pikabot 	 10 / 10	 https://tria.ge/reports/240222-pqlqkshb2w/ 
VMRay 	 Pikabot 	 malicious 	 https://www.vmray.com/analyses/_mb/89dc50024836/report/overview.html 

Please let us know if you have any questions.
------------------------
Send the above message to the certificate provider. 
This report should be sent to SSL.com: https://ssl.com/revoke
```

This information is to be provided to the Certificate Issuer using the appropriate abuse report channels (such as email or website). The appropriate channel is provided at the end of the report (see above).

## Using VirusTotal
In version 2, it became possible to query VirusTotal. To use VirusTotal first set up your API key using the appropriate method for your operating system:
```
        On Linux:
        echo "export VT_API_KEY=your_api_key_here" >> ~/.bashrc
        source ~/.bashrc

        On Windows:
        setx VT_API_KEY "your_api_key"

        On MacOS:
        echo "export VT_API_KEY=your_api_key_here" >> ~/.zprofile
        source ~/.zprofile
```

Once the API key is configured as an environment variable the following command will generate a report:
```
certReport --hash 89dc50024836f9ad406504a3b7445d284e97ec5dafdd8f2741f496cac84ccda9 --service virustotal
```

Alternatively, the switches can be simplified:

```
certReport -# 89dc50024836f9ad406504a3b7445d284e97ec5dafdd8f2741f496cac84ccda9 -s VT
```
Both commands will return the following report: 
```
---------------------------------
Greetings,
 We identified a malware signed with a  SSL.com EV Code Signing Intermediate CA RSA R3 certificate. 
The malware sample is available on VirusTotal here: https://www.virustotal.com/gui/file/89dc50024836f9ad406504a3b7445d284e97ec5dafdd8f2741f496cac84ccda9/detection

Here are the signature details:
Name: A.P.Hernandez Consulting s.r.o.
Issuer:  SSL.com EV Code Signing Intermediate CA RSA R3
Serial Number: 56 B6 29 CD 34 BC 78 F6
Thumbprint: 743AF0529BD032A0F44A83CDD4BAA97B7C2EC49A
Valid From: 2017-05-31 18:14:37
Valid Until: 2042-05-30 18:14:37

The malware was tagged as a peexe, long-sleeps, spreader, detect-debug-environment, service-scan, overlay, revoked-cert, signed and checks-user-input.
The malware was detected by 50 out of 74 antivirus engines.
The malware was classified as trojan by 30 detection engines.
The file was flagged as pikabot by 23 detection engines, zusy by 6 detection engines and gdfvt by 2 detection engines

This file was found during our investigation and had the following suspicious indicators:
 - The file triggered the following high IDS rules:
	- ET CNC Feodo Tracker Reported CnC Server group 1
	- ET CNC Feodo Tracker Reported CnC Server group 2

Please let us know if you have any questions.
------------------------
Send the above message to the certificate provider. 
This report should be sent to SSL.com: https://ssl.com/revoke
```

As stated previously, it is recommended to add additional bulletpoints near the end of the report. Additional bulletpoints should include findings from your own investigation. These details can help provide decision support for the certificate provider.

## Database
In version 3, a database was stored with information about all certs processed with certReport. This database contains most of the details which occur in the report. When running the command the user can use the option `-t` and supply a malware family. If the user does so, the report will add that user supplied name to the database and will check the database for any other instances of that malware name; when there are matches, it will augment the report with information about how many times that malware has been reported. For example, it could print a message like the following near the bottom of the report:

```
We have reported this same malware to SSL.com 2 times. We have reported the malware to other providers 10 times.
```

As of the current version, the database needs to be viewed or managed with a SQLite database viewer. It cannot be viewed or managed within the program.

NOTE: If the user runs the application with the same hash, the first instance of the hash will be removed from the database and replaced with the new information.

### Where is it?
The database is created in a folder in the user's home directory. The folder will be named "certReport" and the database will be named "certReport.db".

## Contributing
Please feel free to suggest changes to the script for additional certificate provider email addresses or methods of reporting. Half of the battle in reporting is finding where certificates should be submitted.

# Why Report?
Starting in 2018, the majority of certificates were no longer stolen, but they are issued to impostors (this case is argued in a scholarly article here: http://users.umiacs.umd.edu/~tdumitra/papers/WEIS-2018.pdf). I call these "Impostor Certs". 
In 2023, I published my research into 50 certificates used by one actor. My findings confirmed that certificates are used to sign multiple malware families: https://squiblydoo.blog/2023/05/12/certified-bad/.
In 2024, I published an article on Impostor certs, after having revoked 100 certificates used to sign the same malware, that article can be read here: https://squiblydoo.blog/2024/05/13/impostor-certs/.

The TLDR is that multiple actors use the same certificate and reporting a certificate raises the cost of signing for all threat actors and it can impact multiple malware campaigns.
