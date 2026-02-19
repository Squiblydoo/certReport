import pytest
import requests
import json
import os
from certReport.main import process_virustotal_data, process_malwarebazaar_data, query_virustotal, query_malwarebazaar

VT_API_KEY = os.getenv('VT_API_KEY')
MB_API_KEY = os.getenv('MB_API_KEY')

signed_hash = '89dc50024836f9ad406504a3b7445d284e97ec5dafdd8f2741f496cac84ccda9'
unsigned_hash = 'eec61b37516a902f999d664590ae8538794f2bbf5f454be52c837cf52760dbfa'

signed_VT_result = {'hash': '89dc50024836f9ad406504a3b7445d284e97ec5dafdd8f2741f496cac84ccda9', 'subject_cn': 'A.P.Hernandez Consulting s.r.o.', 'issuer_cn': ' SSL.com EV Code Signing Intermediate CA RSA R3', 'serial_number': '29 41 D5 F8 75 85 01 F9 DB C4 BA 15 80 58 C3 B5', 'thumbprint': 'AE7AD3DF41DEF3E3169FFA94B2E854D4EFDCEC35', 'valid_from': '04:51 PM 01/25/2024', 'valid_to': '04:51 PM 01/24/2025', 'user_tag': None, 'team_id': None}
signed_MB_result = {'hash': '89dc50024836f9ad406504a3b7445d284e97ec5dafdd8f2741f496cac84ccda9', 'subject_cn': 'A.P.Hernandez Consulting s.r.o.', 'issuer_cn': 'SSL.com EV Code Signing Intermediate CA RSA R3', 'serial_number': '2941d5f8758501f9dbc4ba158058c3b5', 'thumbprint': 'a982917ba6de9588f0f7ed554223d292524e832c1621acae9ad11c0573df54a5', 'valid_from': '2024-01-25T16:51:40Z', 'valid_to': '2025-01-24T16:51:40Z', 'user_tag': None, 'team_id': None}
unsigned_VT_result = {'hash': 'eec61b37516a902f999d664590ae8538794f2bbf5f454be52c837cf52760dbfa', 'subject_cn': None, 'issuer_cn': None, 'serial_number': None, 'thumbprint': None, 'valid_from': None, 'valid_to': None, 'user_tag': None}
unsigned_MB_result = {'hash': 'eec61b37516a902f999d664590ae8538794f2bbf5f454be52c837cf52760dbfa', 'subject_cn': None, 'issuer_cn': None, 'serial_number': None, 'thumbprint': None, 'valid_from': None, 'valid_to': None, 'user_tag': None} 
def test_signed_file_processing_VT():
    data = query_virustotal(signed_hash)
    result = process_virustotal_data(data, signed_hash, None, False)
    assert result == signed_VT_result

def test_unsigned_file_processing_VT():
    data = query_virustotal(unsigned_hash)
    result = process_virustotal_data(data, unsigned_hash, None, False)
    assert result == None

def test_signed_file_processing_MB():
    data = query_malwarebazaar(signed_hash)
    result = process_malwarebazaar_data(data, signed_hash, None, False)
    assert result == signed_MB_result

def test_unsigned_file_processing_MB():
    data = query_malwarebazaar(unsigned_hash)
    result = process_malwarebazaar_data(data, unsigned_hash, None, False)
    assert result == None