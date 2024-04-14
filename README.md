# CertReport

This script is intended to reduce the load of effort required to report authenticode certificates.
That is, if the file is on MalwareBazzar, a user can use the script to generate information to submit to the Certificate Issuer. For example:
Calling the script and passing in a SHA256 like this:<br>
`.\certReport 89dc50024836f9ad406504a3b7445d284e97ec5dafdd8f2741f496cac84ccda9`

Will print the following information to the console:

```
Greetings,
 We identified a malware signed with an SSL.com EV Code Signing Intermediate CA RSA R3 certificate. 
The malware sample is available on MalwareBazaar here: https://bazaar.abuse.ch/sample/89dc50024836f9ad406504a3b7445d284e97ec5dafdd8f2741f496cac84ccda9
Here are the signature details:
Name: A.P.Hernandez Consulting s.r.o.
Issuer: SSL.com EV Code Signing Intermediate CA RSA R3
Serial Number: 2941d5f8758501f9dbc4ba158058c3b5
SHA256 Thumbprint: a982917ba6de9588f0f7ed554223d292524e832c1621acae9ad11c0573df54a5

The malware was tagged as exe, Pikabot and signed.
MalwareBazaar submitted the file to multiple public sandboxes, the links to the sandbox results are below:
Sandbox  / Malware Family        /  Verdict      / Analysis URL
Intezer          None    unknown         https://analyze.intezer.com/analyses/c4915ef4-198f-4aba-81ed-81b29cd4dce6?utm_source=MalwareBazaar 
Triage   pikabot         10 / 10         https://tria.ge/reports/240222-pqlqkshb2w/ 
VMRay    Pikabot         malicious       https://www.vmray.com/analyses/_mb/89dc50024836/report/overview.html 

Please let us know if you have any questions.
------------------------
Send the above message to the certificate provider. Here is where to send some:
This report should be sent to SSL.com: https://ssl.com/revoke
```

This information is to be provided to the Certificate Issuer using the appropriate abuse report channels (such as email or website).
This workflow provides the Certificate Issuer information about the certificate and other details to help their decision support leading to the revocation of certificate

# Report in Detail
The script uses MalwareBazaar's API to pull information from MalwareBazaar. Currently, the script prioritizes pulling back information from sandboxes that have public reports. The goal is to provide as much information to support decisions as well as allowing the Certificate Issuer to have additional avenues for investigation.<br>
When reporting certificates, Certificate Issuers need to know the Serial Number and Thumbprint associated with the malicious certificate. This report makes that easily accessible.<br>
The report also raises the "Tags" from MalwareBazaar. These tags are associated with any human or machine placed tags that provide searchable indicators. In the example above, the Pikabot sample surfaces "exe", "Pikabot", and "signed". I recommend cleaning up the report manually and including additional details if possible, but it is not required. The benefit in doing so is that it provides the Certificate Issuer more decision support and increases the likelihood that they they will revoke the certificate.<br>

## Contributing
Please feel free changes to the script for additional certificate provider email addresses or methods of reporting. Half of the battle in reporting is finding where certificates should be submitted.

# Why Report?
Starting in 2018, the majority of certificates were no longer stolen, but they are issued to imposters. I call these "Imposter Certs" or "Sus Certs". Squiblydoo's research and findings can be read here: https://squiblydoo.blog/2023/05/12/certified-bad/, a scholarly article on this behavior can be found here: http://users.umiacs.umd.edu/~tdumitra/papers/WEIS-2018.pdf

The TLDR is that multiple actors use the same certificate and reporting a certificate raises the cost of signing for all threat actors and it can impact multiple malware campaigns.
