## Overview

This repository provides a **single Python entrypoint**, **`suci_tool.py`**, for SUPI/SUCI conceal and deconceal (CLI and graphical UI). The GUI is implemented inside that module—there is no separate `gui_app.py`.

**Recommended usage**

| Platform | Prefer |
|----------|--------|
| Linux / macOS | `./suci_tool.sh …` (creates `./env` and runs `env/bin/python suci_tool.py`) |
| Windows | `suci_tool.bat …` or `run_gui.bat` (same as `suci_tool.bat` with no args) |

You can also run `python suci_tool.py` after `./env` exists or after `python suci_tool.py --setup-env`.

**Repository layout (important files)**

- `suci_tool.py` — bootstrap, CLI, and GUI
- `suci_tool.sh` / `suci_tool.bat` — launch with the project virtualenv
- `requirements.txt` — Pip deps installed into `env/` by `--setup-env`
- `run_gui.bat` — thin wrapper that calls `suci_tool.bat`

Older filenames **`concealing_tool.py`**, **`concealing_tool.sh`**, **`concealing_tool.bat`**, and **`gui_app.py`** are removed; replace them with the `suci_tool*` names above.

## 1 Requirements

**All platforms**

- Python **3.10+** (64-bit recommended on Windows).
- **Git** on `PATH` (to clone PyCrates and CryptoMobile).
- **Rust toolchain** (often required to **build** CryptoMobile from source): install from [rustup.rs](https://rustup.rs/). On Windows, Visual Studio Build Tools may also be needed for native compilation.
- **OpenSSL** with supported `curve25519` and `secp256k1` when generating keys (commands below are shown for Linux/macOS shells; on Windows use Git Bash, WSL, or equivalent OpenSSL binaries).

**Linux / macOS**

- Typical build deps for Python wheels / Rust (e.g. `python3-venv`, compilers): install per your distribution if `pip` or `cargo` builds fail.

**Windows 11**

- [Git for Windows](https://git-scm.com/download/win), Python from [python.org](https://www.python.org/) or the Microsoft Store (ensure **Add python.exe to PATH** during setup).
- Prefer **`suci_tool.bat`** or **`run_gui.bat`** from **cmd** / **PowerShell** so the correct `./env` interpreter is always used.

### Recommended launchers (avoid mixing system Python with `./env`)

**Linux / macOS**

```shell
chmod +x suci_tool.sh
./suci_tool.sh                    # GUI by default
./suci_tool.sh --help
./suci_tool.sh --conceal ...
```

The script creates `./env` when missing (or when imports fail), runs `suci_tool.py --setup-env` once via **`python3`**, then **`exec`**’s `env/bin/python suci_tool.py` with your arguments.

**Windows**

```bat
suci_tool.bat
suci_tool.bat --help
suci_tool.bat --conceal ...
```

Uses **`python`** or **`py -3`** on `PATH` only for the initial `--setup-env`, then always runs **`env\Scripts\python.exe suci_tool.py`**.

## 2 Automatic environment (`env/`)

Everything lives in **`suci_tool.py`**. Dependencies are installed into a project-local virtual environment **`env/`** when needed:

1. On first use (**GUI**, **conceal** / **deconceal** via CLI or GUI buttons), if dependencies are missing (`pycrate_mobile`, `CryptoMobile`, and for the GUI also **customtkinter**), the tool runs the built-in bootstrap, then **restarts** using `env\Scripts\python.exe` (Windows) or `env/bin/python` (Unix).
2. To create or refresh the environment explicitly:

```shell
python suci_tool.py --setup-env
```

Options:

- `python suci_tool.py --setup-env --reinstall-git` — force a fresh clone and reinstall of PyCrates + CryptoMobile.
- `python suci_tool.py --setup-env --full-clone` — full git history instead of shallow clones.

After the environment exists, you can still install pinned Pip packages with:

```shell
pip install -r requirements.txt
```

(use the `env` interpreter if you are not activated).

To disable automatic bootstrap (fail fast if deps are missing):

```shell
python suci_tool.py --no-bootstrap --conceal ...
```

Equivalent environment variable: `SUCI_TOOL_NO_BOOTSTRAP=1`.

### 2.1 What gets installed

`--setup-env` creates `env/`, upgrades pip tooling, installs `requirements.txt`, then clones **PyCrates** and **CryptoMobile** from GitHub and installs them (same as the old manual bash flow).

### 2.2 Activate the environment manually (optional)

**Linux / macOS**

```shell
source env/bin/activate
python suci_tool.py --help
```

**Windows (cmd)**

```bat
env\Scripts\activate.bat
python suci_tool.py --help
```

**Windows (PowerShell)**

```powershell
.\env\Scripts\Activate.ps1
python suci_tool.py --help
```

## 3 GUI

With **no arguments**, `suci_tool.py` opens the graphical interface:

**Linux / macOS**

```shell
./suci_tool.sh
```

or:

```shell
python suci_tool.py
```

**Windows**

```bat
suci_tool.bat
```

or:

```bat
run_gui.bat
```

or:

```bat
python suci_tool.py
```

`--gui` is optional (same as no arguments).

The GUI exposes **Conceal**, **Deconceal**, and a **Keys** tab to generate PEM pairs without OpenSSL.

### 3.1 Generate keys (Python — Linux & Windows)

Equivalent to the OpenSSL flows below, using **cryptography** (no `openssl` binary required):

```shell
./suci_tool.sh --gen-keys profile_a --keys-dir keys
./suci_tool.sh --gen-keys profile_b --keys-dir keys
```

**Windows**

```bat
suci_tool.bat --gen-keys profile_a --keys-dir keys
suci_tool.bat --gen-keys profile_b --keys-dir keys
```

Or use `python suci_tool.py` from an environment where **cryptography** is installed. Aliases: `a` for `profile_a`, `b` for `profile_b`.

Default filenames match the README: `curve25519.pem` / `curve25519_pub.pem`, and `secp256r1.pem` / `secp256r1_pub.pem`.

## 4 curve25519 key (Profile A)

### 4.1 Create the private and public keys (OpenSSL alternative)

You can skip this section if you used **`--gen-keys profile_a`** or the GUI **Keys** tab.

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

### 4.2 SUPI concealing using the public key

```shell
python suci_tool.py --conceal \
   --supi_type 0 \
   --routing_indicator 0000 \
   --scheme_id 1 \
   --key_id 1 \
   --plmn 72417 \
   --msin 0000000001 \
   --json_file suci_json.json \
   --public_key_file keys/curve25519_pub.pem
```

### 4.3 Deconcealing SUCI to SUPI using the private key

Using the suci string (using the suci string generated in the previous step):

```shell
python suci_tool.py --deconceal \
   --suci_string suci-0-724-17-0000-1-1-2682E6EE2AB2D98557C6B69438D47970A9BD5ACB0A3C4EB61D9FE497414DCA783556227BD4BC80E8320F95985D  \
   --private_key_file keys/curve25519.pem
```

Using the `suci_json.json` file generated in the 4.2 with `--json_file` option:

```shell
python suci_tool.py --deconceal \
   --json_file suci_json.json --private_key_file keys/curve25519.pem 
```


## 5 secp256k1 key (Profile B)

### 5.1 Create the private and public keys (OpenSSL alternative)

You can skip this section if you used **`--gen-keys profile_b`** or the GUI **Keys** tab.

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

### 5.2 SUPI concealing using the public key

```shell
python suci_tool.py --conceal \
   --supi_type 0 \
   --routing_indicator 0000 \
   --scheme_id 2 \
   --key_id 2 \
   --plmn 72417 \
   --msin 0000000001 \
   --json_file suci_json.json \
   --public_key_file keys/secp256r1_pub.pem
```

### 5.3 Deconcealing SUCI to SUPI using the private key

Using the suci string (using the suci string generated in the previous step):

```shell
python suci_tool.py --deconceal \
   --suci_string suci-0-724-17-0000-2-2-0227A73174F1A9383CBAE83BA5852D1ACCADD55AEC7333BC47B40A02DAD99AD15BF8412D19A715497ED4A1C1B3B1  \
   --private_key_file keys/secp256r1.pem
```

Using the `suci_json.json` file generated in the 5.2 with `--json_file` option:

```shell
python suci_tool.py --deconceal \
   --json_file suci_json.json --private_key_file keys/secp256r1.pem
```
