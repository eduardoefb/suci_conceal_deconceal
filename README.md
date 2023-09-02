## 1 Requirements:
- Linux;
- python3, python3-pip and python3-venv;
- OpenSSL with supported `curve25519` and `secp256k1` algorithms.

## 2 Install the required dependencies
Create a virtual environment to install the necessary libraries:
```shell
python3 -m venv env
```

Activate the environment:
```shell
source env/bin/activate
```

Install the required libraries
```shell
/bin/bash << EOF 
pip3 install setuptools_rust
pip3 install cryptography
cwd=`pwd`
tmpdir=`mktemp -d`
cd ${tmp_dir}
git clone https://github.com/P1sec/pycrate.git
cd pycrate 
git checkout
python3 setup.py install

cd ${tmp_dir}
git clone https://github.com/mitshell/CryptoMobile.git
cd CryptoMobile 
git checkout
python3 setup.py install
cd ${cwd}
rm -rf ${tmp_dir}
EOF

```

## 3 curve25519 key (Profile A)

### 3.1 Create the private and public keys:
Create the private key:
```shell
if [ -f keys ]; then \rm -f keys; fi; if [ ! -d keys ]; then mkdir keys; fi
openssl genpkey -algorithm X25519 -out keys/curve25519.pem
```

Retrive the public key from the private key:
```shell
openssl pkey -in keys/curve25519.pem -pubout -outform PEM -out keys/curve25519_pub.pem
```

To retrieve the bytes for both the public and private keys:
```shell
openssl pkey -in keys/curve25519.pem -text -noout
```

### 3.2 SUPI concealing using the public key
```shell
python3 concealing_tool.py --conceal \
   --supi_type 0 \
   --routing_indicator 0000 \
   --scheme_id 1 \
   --key_id 1 \
   --plmn 72417 \
   --msin 0000000001 \
   --json_file suci_json.json \
   --public_key_file keys/curve25519_pub.pem
```

### 3.3 Deconcealing SUCI to SUPI using the private key

Using the suci string (using the suci string generated in the previous step):
```shell
python3 concealing_tool.py --deconceal \
   --suci_string suci-0-724-17-0000-1-1-2682E6EE2AB2D98557C6B69438D47970A9BD5ACB0A3C4EB61D9FE497414DCA783556227BD4BC80E8320F95985D  \
   --private_key_file keys/curve25519.pem
```

Using the `suci_json.json` file generated in the 3.2 with `--json_file` option:
```shell
python3 concealing_tool.py --deconceal \
   --json_file suci_json.json --private_key_file keys/curve25519.pem 
```


## 4 secp256k1 key (Profile B)

### 4.1 Create the private and public keys:
Create the private key:
```shell
if [ -f keys ]; then \rm -f keys; fi; if [ ! -d keys ]; then mkdir keys; fi
openssl ecparam -name secp256k1 -out keys/secp256k1_tmp.pem
openssl ecparam -name prime256v1 -in keys/secp256k1_tmp.pem -genkey -noout -out keys/secp256k1-key_tmp.pem 
cat keys/secp256k1_tmp.pem keys/secp256k1-key_tmp.pem > keys/secp256r1.pem
rm keys/sec*_tmp.pem 
```

Retrive the public key from the private key:
```shell
openssl ec -in keys/secp256r1.pem -pubout -conv_form compressed -out keys/secp256r1_pub.pem
```

To retrieve the bytes for both the public and private keys:
```shell
openssl ec -in keys/secp256r1.pem -text -noout -conv_form compressed
```

### 4.2 SUPI concealing using the public key
```shell
python3 concealing_tool.py --conceal \
   --supi_type 0 \
   --routing_indicator 0000 \
   --scheme_id 2 \
   --key_id 2 \
   --plmn 72417 \
   --msin 0000000001 \
   --json_file suci_json.json \
   --public_key_file keys/secp256r1_pub.pem
```

### 4.3 Deconcealing SUCI to SUPI using the private key

Using the suci string (using the suci string generated in the previous step):
```shell
python3 concealing_tool.py --deconceal \
   --suci_string suci-0-724-17-0000-2-2-0227A73174F1A9383CBAE83BA5852D1ACCADD55AEC7333BC47B40A02DAD99AD15BF8412D19A715497ED4A1C1B3B1  \
   --private_key_file keys/secp256r1.pem
```

Using the `suci_json.json` file generated in the 4.2 with `--json_file` option:
```shell
python3 concealing_tool.py --deconceal \
   --json_file suci_json.json --private_key_file keys/secp256r1.pem
```