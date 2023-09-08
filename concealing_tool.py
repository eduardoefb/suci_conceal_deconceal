#!/usr/bin/python3

# Reference: https://labs.p1sec.com/2020/06/26/5g-supi-suci-and-ecies/

# Needed libraries:
#   https://github.com/P1sec/pycrate.git
#   https://github.com/mitshell/CryptoMobile.git

import binascii
from pycrate_mobile.TS24501_IE import *
from CryptoMobile.ECIES import ECIES_UE,ECIES_HN,ECDH_SECP256R1
from pycrate_mobile.TS24008_IE import decode_bcd
from cryptography.hazmat.primitives import serialization
import argparse 
import sys
import json
import os

def generate_suci(  
                    scheme_id = None, 
                    hn_pubkey = None, 
                    imsi = None, 
                    supi = None, 
                    routing_indicator = None, 
                    key_id = None, 
                    plmn = None, 
                    msin = None, 
                    supi_type = None,
                    json_file = None
                ):

    # Generate the supi encrypted:
    if scheme_id == 0:
        suci = None

        suci_string = f"suci-{supi_type}-{plmn[:3]}-{plmn[3:5]}-{routing_indicator}-{scheme_id}-0-{msin}"
        
        #suci_string f"suci-0-724-17-0000-0-0-0000000001"
    elif scheme_id == 1:
        ue_ecies = ECIES_UE(profile='A')
    elif scheme_id == 2:
        ue_ecies = ECIES_UE(profile='B')
        
    if scheme_id in [1, 2]:
        ue_ecies.generate_sharedkey(hn_pubkey)
        ue_pubkey, ue_encmsin, ue_mac = ue_ecies.protect(supi['Value']['Output'].to_bytes())
        suci = FGSIDSUPI(val={ 'Fmt': FGSIDFMT_IMSI, \
                            'Value': { 'PLMN': f"{plmn}", \
                            'ProtSchemeID': int(scheme_id), \
                            'Output': { 'ECCEphemPK': ue_pubkey, \
                            'CipherText': ue_encmsin, \
                            'MAC': ue_mac}}})

        # Request example:
        ue_key_text = binascii.hexlify(ue_pubkey).decode().upper()
        enc_msin_text = binascii.hexlify(ue_encmsin).decode().upper()
        mac_text = binascii.hexlify(ue_mac).decode().upper()

    print(f"\n####################SUPI###############\n{imsi}")

    if scheme_id in [1, 2]:
        print(f"\n####################SUCI###############\n{suci}")
    
    if scheme_id in [1, 2]:
        if hn_privkey:
            print(f"\n#################PRIVATE KEY###########\n{hn_privkey.hex()}")

        print(f"\n#################PUBLIC KEY############\n{hn_pubkey.hex()}")
        suci_string = f"suci-{supi_type}-{plmn[:3]}-{plmn[3:6]}-{routing_indicator}-{scheme_id}-{key_id}-{ue_key_text}{enc_msin_text}{mac_text}"

    net_string = f"5G:mnc{plmn[3:6]}.mcc{plmn[:3]}.3gppnetwork.org"
    print(f"\n############SUCI STRING################\n{suci_string}")

    create_suci_json(json_file, suci_string, net_string)
    return suci  

def create_suci_json(json_file, suci_string, net_string):
    if json_file is not None:
        json_fp = open(str(json_file), "w")
        json_str = """{\n   "supiOrSuci": \"""" + str(suci_string) + """\",\n   "servingNetworkName": \""""+ str(net_string) +"""\"\n}\n"""
        json_fp.write(json_str)
        json_fp.close()    

def get_suci_from_json(json_file):
    if os.path.exists(json_file) and args.deconceal:
        with open(json_file, 'r') as fp:
            data = json.load(fp)        

        return str(data['supiOrSuci'])    
    else:
        return None

def generate_suci_from_str(  
                    suci_str = None,
                    json_file = None
                ):
    
    if json_file is not None:
        suci_str = get_suci_from_json(json_file)
        
    suci_string = suci_str
    supi_type = suci_str.split("-")[1]
    suci_mcc = suci_str.split("-")[2]
    suci_mnc = suci_str.split("-")[3]
    routing_indicator = suci_str.split("-")[4]
    scheme_id = int(suci_str.split("-")[5])
    key_id = int(suci_str.split("-")[6])
    pscheme_output = suci_str.split("-")[7]

    # Generate the supi encrypted:
    if scheme_id == 0:
        suci = None
        suci_string = f"suci-{supi_type}-{plmn[:3]}-{plmn[3:5]}-{routing_indicator}-{scheme_id}-0-{msin}"        
    elif scheme_id == 1:
        try:
            ue_ecies = ECIES_UE(profile='A')
            ue_pubkey = bytes.fromhex(str(pscheme_output[:64]).strip())
            ue_encmsin = bytes.fromhex(str(pscheme_output[64:74]).strip())
            ue_mac = bytes.fromhex(str(pscheme_output[74:]).strip())        
        except ValueError as ex:
            print(f"Invalid SUCI String: {ex}")
            sys.exit(1)
    elif scheme_id == 2:
        try:
            ue_ecies = ECIES_UE(profile='B')
            ue_pubkey = bytes.fromhex(str(pscheme_output[:66]).strip())
            ue_encmsin = bytes.fromhex(str(pscheme_output[66:76]).strip())
            ue_mac = bytes.fromhex(str(pscheme_output[76:]).strip())        
        except ValueError as ex:
            print(f"Invalid SUCI String: {ex}")
            sys.exit(1)
        
    if scheme_id in [1, 2]:
        ue_ecies.generate_sharedkey(hn_pubkey)

        suci = FGSIDSUPI(val={ 'Fmt': FGSIDFMT_IMSI, \
                            'Value': { 'PLMN': f"{plmn}", \
                            'ProtSchemeID': int(scheme_id), \
                            'Output': { 'ECCEphemPK': ue_pubkey, \
                            'CipherText': ue_encmsin, \
                            'MAC': ue_mac}}})

        # Request example:
        ue_key_text = binascii.hexlify(ue_pubkey).decode().upper()
        enc_msin_text = binascii.hexlify(ue_encmsin).decode().upper()
        mac_text = binascii.hexlify(ue_mac).decode().upper()
    
    if scheme_id in [1, 2]:
        print(f"\n####################SUCI###############\n{suci}")
    
    if scheme_id in [1, 2]:
        if hn_privkey:
            print(f"\n#################PRIVATE KEY###########\n{hn_privkey.hex()}")

        print(f"\n#################PUBLIC KEY############\n{hn_pubkey.hex()}")
        suci_string = f"suci-{supi_type}-{plmn[:3]}-{plmn[3:6]}-{routing_indicator}-{scheme_id}-{key_id}-{ue_key_text}{enc_msin_text}{mac_text}"

    net_string = f"5G:mnc{plmn[3:6]}.mcc{plmn[:3]}.3gppnetwork.org"
    print(f"\n############SUCI STRING################\n{suci_string}")

    create_suci_json(json_file, suci_string, net_string) 
    return suci      

def decode_suci(scheme_id = None, hn_privkey = None, imsi = None, suci = None):
    if scheme_id == 0:
        return None
    elif scheme_id == 1:
        hn_ecies = ECIES_HN(hn_privkey, profile='A')
    elif scheme_id == 2:
        hn_ecies = ECIES_HN(hn_privkey, profile='B')

    rx_suci = FGSIDSUPI()
    rx_suci.from_bytes(suci.to_bytes())
    #print(rx_suci)
    
    # Then decrypts the MSIN part of the SUCI
    dec_msin = hn_ecies.unprotect(rx_suci['Value']['Output']['ECCEphemPK'].get_val(), rx_suci['Value']['Output']['CipherText'].get_val(), rx_suci['Value']['Output']['MAC'].get_val()) 

    # The original IMSI is retrieved from the PLMN ID and decrypted MSIN
    try:
        dec_imsi = suci['Value']['PLMN'].decode() + decode_bcd(dec_msin)
    except:        
        dec_imsi = "***Deconcealing error!***"
        
    print(f"\n##########DECONCEALED SUPI#############\n{dec_imsi}")
    return(dec_imsi)

def load_private_key(scheme_id = None, private_key_file = None):

    # Load private key from file and get its public key
    if scheme_id in [1, 2]:
        with open(str(private_key_file), "rb") as key_file:
            key_data = key_file.read()
        private_key = serialization.load_pem_private_key(key_data, password=None)

    if scheme_id == 0:
        hn_privkey = hn_pubkey = None

    elif scheme_id == 1:        
        hn_privkey = private_key.private_bytes_raw()
        hn_pubkey = private_key.public_key().public_bytes_raw()
        
    elif scheme_id == 2:
        ec = ECDH_SECP256R1()
        ec.PrivKey = private_key
        hn_pubkey = bytes(ec.get_pubkey())
        hn_privkey = bytes(ec.get_privkey())  
    
    return hn_privkey, hn_pubkey

def load_public_key(scheme_id = None, public_key_file = None):
    if scheme_id in [1, 2]:
        with open(str(public_key_file), "rb") as key_file:
            key_data = key_file.read()
        public_key = serialization.load_pem_public_key(key_data)

    if scheme_id == 0:
        hn_pubkey = None

    elif scheme_id == 1:        
        hn_pubkey = public_key.public_bytes_raw()
        
    elif scheme_id == 2:        
        hn_pubkey = public_key.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        hn_pubkey = hn_pubkey[26:]
    return hn_pubkey

# Parser:
parser = argparse.ArgumentParser(description='Input data for open5gs')
parser.add_argument('--conceal', action='store_true', help='Use this option to conceal')
parser.add_argument('--deconceal', action='store_true', help='Use this option to deconceal')
parser.add_argument('--supi_type', type=str, required=False, help='SUPI type. 0 = IMSI, 1 = Network Access Identifier (NAI)')
parser.add_argument('--routing_indicator', type=str, required=False, help='Routing indicator. Ex: 0000')
parser.add_argument('--scheme_id', type=int, required=False, help='Scheme ID: 0 = null-scheme, 1 = Profile A, 2 = Profile B', choices=[0, 1, 2])
parser.add_argument('--key_id', type=int, required=False, help='Key ID')
parser.add_argument('--plmn', type=str, required=False, help='PLMN. Ex: 72417')
parser.add_argument('--msin', type=str, required=False, help='MSIN. Ex: 0000000001')
parser.add_argument('--private_key_file', type=str, required=False, help='Private key file')
parser.add_argument('--public_key_file', type=str, required=False, help='Public key file')
parser.add_argument('--suci_string', type=str, required=False, help='Suci string')
parser.add_argument('--json_file', type=str, required=False, help='JSON file for suci input - for deconcealing, or for output in the concealing')

args = parser.parse_args()

if args.conceal and args.deconceal:
    parser.error('--conceal and --deconceal can\'t be used at the same time')

elif args.conceal:
    if args.supi_type is None: 
         parser.error('--supi_type is requred when --conceal is used')
    if args.routing_indicator is None: 
         parser.error('--routing_indicator requred when --conceal is used')
    if args.scheme_id is None: 
         parser.error('--scheme_id requred when --conceal is used')       
    if args.key_id is None: 
         parser.error('--key_id requred when --conceal is used')
    if args.plmn is None: 
         parser.error('--plmn requred when --conceal is used')
    if args.msin is None: 
         parser.error('--msin requred when --conceal is used')
    if args.scheme_id in [1, 2] and args.private_key_file is None and args.public_key_file is None:
        parser.error('--private_key_file or --public_key_file are required for scheme_id 1 or 2 and when --conceal is used')    

elif args.deconceal:
    if not args.suci_string and not args.json_file:
         parser.error('--json_file or --suci_string are required when --deconceal is used')
    if args.suci_string and args.json_file:
         parser.error('--json_file and --suci_string can\'t be used at the same time when --deconceal is used')
    if args.supi_type: 
         parser.error('--supi_type not supported when --deconceal is used')
    if args.routing_indicator: 
         parser.error('--routing_indicator not supported when --deconceal is used')
    if args.scheme_id: 
         parser.error('--scheme_id not supported when --deconceal is used')       
    if args.key_id: 
         parser.error('--key_id not supported when --deconceal is used')
    if args.plmn: 
         parser.error('--plmn not supported when --deconceal is used')
    if args.msin: 
         parser.error('--msin not supported when --deconceal is used')
    if args.public_key_file: 
         parser.error('--public_key_file not supported when --suci_string is used')
    if args.private_key_file is None: 
         parser.error('--private_key_file is requred when --deconceal is used')    
else:
    parser.error('--conceal or --deconceal are mandatory')
    
suci_str = None
supi_type = args.supi_type    
routing_indicator = args.routing_indicator
prot_scheme_id = args.scheme_id 
key_id = args.key_id
plmn = args.plmn
msin = args.msin 

if args.suci_string:
    suci_str = args.suci_string

if args.json_file is not None:
    suci_str = get_suci_from_json(args.json_file)    

priv_key = None 
public_key = None 

if args.private_key_file:
    priv_key = args.private_key_file

if args.public_key_file:
    public_key = args.public_key_file

# IMSI
imsi = f"{plmn}{msin}"

# the MSIN part of the IMSI is set as the Output part of the SUPI
supi = FGSIDSUPI(val={ 'Fmt': FGSIDFMT_IMSI, \
                       'Value': {'PLMN': plmn, \
                       'Output': msin}}) 

json_file = None
if args.json_file:
    json_file = str(args.json_file)

# Load the private key and return the hn_priv and public keys
hn_privkey = None 

if suci_str:
    prot_scheme_id = int(suci_str.split("-")[5])
    supi_type = suci_str.split("-")[1]
    mcc = suci_str.split("-")[2]
    mnc = suci_str.split("-")[3]
    plmn = str(mcc) + str(mnc)
    routing_indicator = suci_str.split("-")[4]    
    key_id = int(suci_str.split("-")[6])
    pscheme_output = suci_str.split("-")[7]    

if priv_key:
    hn_privkey, hn_pubkey = load_private_key(scheme_id = prot_scheme_id, private_key_file = priv_key)
elif public_key:
    hn_pubkey = load_public_key(scheme_id = prot_scheme_id, public_key_file = public_key)

if suci_str:
    suci = generate_suci_from_str(suci_str = suci_str, json_file = json_file)    

else:
    suci = generate_suci(scheme_id = prot_scheme_id, hn_pubkey = hn_pubkey, imsi = imsi, supi = supi, routing_indicator = routing_indicator, key_id = key_id, plmn = plmn, msin = msin, supi_type = supi_type, json_file = json_file)

# Decrypt suci
if hn_privkey:
    imsi = decode_suci(scheme_id = prot_scheme_id, hn_privkey = hn_privkey, suci = suci)
