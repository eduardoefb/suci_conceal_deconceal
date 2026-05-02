#!/usr/bin/env python3
# suci_tool.py — SUPI/SUCI conceal & deconceal, key generation, GUI.
# Reference: https://labs.p1sec.com/2020/06/26/5g-supi-suci-and-ecies/
#
# Dependencies: PyCrates + CryptoMobile + cryptography (bootstrap via this file).
# Run with no arguments to open the GUI; use --help for CLI options.

from __future__ import annotations

import argparse
import binascii
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Tuple

_PYCRATE_REPO = "https://github.com/P1sec/pycrate.git"
_CRYPTOMOBILE_REPO = "https://github.com/mitshell/CryptoMobile.git"

# Lazy-loaded crypto stack (allows automatic env/bootstrap before import).
ECIES_HN: Any = None
ECIES_UE: Any = None
ECDH_SECP256R1: Any = None
serialization: Any = None
decode_bcd: Any = None
FGSIDFMT_IMSI: Any = None
FGSIDSUPI: Any = None

_CRYPTO_READY = False


def _project_root() -> Path:
    return Path(__file__).resolve().parent


def _venv_python() -> Path:
    env_dir = _project_root() / "env"
    if sys.platform == "win32":
        return env_dir / "Scripts" / "python.exe"
    return env_dir / "bin" / "python"


def _run_logged(cmd: list[str], *, cwd: Optional[Path] = None) -> None:
    print("+", " ".join(cmd), flush=True)
    subprocess.check_call(cmd, cwd=str(cwd) if cwd else None)


def _which_git_exe() -> str:
    git = shutil.which("git")
    if not git:
        raise RuntimeError(
            "Git was not found on PATH. Install Git (https://git-scm.com/) or your distro package, then retry."
        )
    return git


def _ensure_venv_created() -> Path:
    env_path = _project_root() / "env"
    py = _venv_python()
    if py.exists():
        return py
    env_path.parent.mkdir(parents=True, exist_ok=True)
    _run_logged([sys.executable, "-m", "venv", str(env_path)])
    if not py.exists():
        raise RuntimeError(f"venv created but interpreter missing: {py}")
    return py


def _pip_install(py: Path, *pip_args: str) -> None:
    _run_logged([str(py), "-m", "pip", "install", *pip_args])


def _venv_deps_ok(py: Path) -> bool:
    r = subprocess.run(
        [str(py), "-c", "import pycrate_mobile, CryptoMobile"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return r.returncode == 0


def _install_git_dependencies(py: Path, *, shallow: bool = True) -> None:
    git = _which_git_exe()
    depth = ["--depth", "1"] if shallow else []
    with tempfile.TemporaryDirectory(prefix="suci_deps_") as tmp:
        tmp_path = Path(tmp)
        pycrate_dir = tmp_path / "pycrate"
        cm_dir = tmp_path / "CryptoMobile"
        _run_logged([git, "clone", *depth, _PYCRATE_REPO, str(pycrate_dir)])
        _run_logged([git, "clone", *depth, _CRYPTOMOBILE_REPO, str(cm_dir)])
        _pip_install(py, str(pycrate_dir))
        _pip_install(py, str(cm_dir))


def bootstrap_environment(*, reinstall_git: bool = False, shallow_clone: bool = True) -> Path:
    """
    Create/update ./env, install requirements.txt, clone/build PyCrates + CryptoMobile.
    Returns the path to the venv Python interpreter.
    """
    root = _project_root()
    py = _ensure_venv_created()
    _pip_install(py, "--upgrade", "pip", "setuptools", "wheel")
    req = root / "requirements.txt"
    if req.is_file():
        _pip_install(py, "-r", str(req))
    need_git = reinstall_git or not _venv_deps_ok(py)
    if need_git:
        _install_git_dependencies(py, shallow=shallow_clone)
    _run_logged(
        [
            str(py),
            "-c",
            "import pycrate_mobile, CryptoMobile; print('Imports OK: pycrate_mobile, CryptoMobile')",
        ]
    )
    print(f"\nDone. Use this interpreter:\n  {py}", flush=True)
    return py


def _deps_available() -> bool:
    try:
        return (
            importlib.util.find_spec("pycrate_mobile") is not None
            and importlib.util.find_spec("CryptoMobile") is not None
        )
    except Exception:
        return False


def _allow_auto_bootstrap() -> bool:
    return os.environ.get("SUCI_TOOL_NO_BOOTSTRAP") != "1"


def _can_relaunch_safely() -> bool:
    """True when argv[0] looks like our repo script (not -m, pytest, etc.)."""
    try:
        name = Path(sys.argv[0]).resolve().name.lower()
    except Exception:
        return False
    return name in ("suci_tool.py", "concealing_tool.py")


def _script_path_for_relaunch() -> Path:
    """Script path to pass to the venv interpreter. Falls back to this module if argv[0] is unusual."""
    if _can_relaunch_safely():
        return Path(sys.argv[0]).resolve()
    return Path(__file__).resolve()


def _consume_own_script_argv(argv_rest: list[str]) -> list[str]:
    """
    After re-exec via `venv_python script.py ...`, sys.argv[1:] begins with the script path again.
    Strip leading script path when Python was started as `venv_python script.py ...`.
    """
    if not argv_rest:
        return argv_rest
    try:
        cand = Path(argv_rest[0]).resolve()
        tool = Path(__file__).resolve()
        if cand.samefile(tool):
            return argv_rest[1:]
    except Exception:
        pass
    return argv_rest


def _ensure_runtime_environment() -> None:
    """Create env/, install deps in-process, then continue in env python if needed."""
    if _deps_available():
        return
    if not _allow_auto_bootstrap():
        print(
            "Missing dependencies (pycrate_mobile / CryptoMobile). Run:\n"
            f'  "{sys.executable}" "{Path(__file__).resolve()}" --setup-env',
            file=sys.stderr,
        )
        raise SystemExit(1)

    try:
        bootstrap_environment(reinstall_git=False, shallow_clone=True)
    except (RuntimeError, subprocess.CalledProcessError) as e:
        print(f"Dependency setup failed: {e}", file=sys.stderr)
        raise SystemExit(1) from e

    env_py = _venv_python()
    if env_py.exists() and Path(sys.executable).resolve() != env_py.resolve():
        script = _script_path_for_relaunch()
        rc = subprocess.call([str(env_py), str(script)] + list(sys.argv[1:]))
        raise SystemExit(rc)

    if not _deps_available():
        print(
            "Dependencies still unavailable after setup. Try:\n"
            f'  "{env_py}" "{Path(__file__).resolve()}" --setup-env --reinstall-git',
            file=sys.stderr,
        )
        raise SystemExit(1)


def _load_crypto_dependencies() -> None:
    """Import CryptoMobile / PyCrates / cryptography (after optional bootstrap)."""
    global _CRYPTO_READY, ECIES_HN, ECIES_UE, ECDH_SECP256R1, serialization, decode_bcd, FGSIDFMT_IMSI, FGSIDSUPI
    if _CRYPTO_READY:
        return
    _ensure_runtime_environment()

    from CryptoMobile.ECIES import ECDH_SECP256R1 as _ECDH, ECIES_HN as _EHN, ECIES_UE as _EUE
    from cryptography.hazmat.primitives import serialization as _serialization
    from pycrate_mobile.TS24008_IE import decode_bcd as _decode_bcd
    from pycrate_mobile.TS24501_IE import FGSIDFMT_IMSI as _FGFMT
    from pycrate_mobile.TS24501_IE import FGSIDSUPI as _FGSUPI

    ECIES_HN, ECIES_UE, ECDH_SECP256R1 = _EHN, _EUE, _ECDH
    serialization = _serialization
    decode_bcd = _decode_bcd
    FGSIDFMT_IMSI, FGSIDSUPI = _FGFMT, _FGSUPI
    _CRYPTO_READY = True


# ---------------------------------------------------------------------------
# Result types (CLI prints match legacy output when verbose=True)
# ---------------------------------------------------------------------------


@dataclass
class ConcealResult:
    imsi: str
    suci_obj: Optional[Any]
    suci_string: str
    net_string: str
    hn_pubkey_hex: Optional[str]
    hn_privkey_hex: Optional[str]


@dataclass
class DeconcealResult:
    dec_imsi: Optional[str]
    suci_obj: Optional[Any]
    scheme_id: int


def create_suci_json(json_file: Optional[str], suci_string: str, net_string: str) -> None:
    if json_file is None:
        return
    json_str = (
        '{\n   "supiOrSuci": "'
        + str(suci_string)
        + '",\n   "servingNetworkName": "'
        + str(net_string)
        + '"\n}\n'
    )
    with open(str(json_file), "w", encoding="utf-8") as json_fp:
        json_fp.write(json_str)


def get_suci_from_json(json_file: str) -> Optional[str]:
    if not os.path.exists(json_file):
        return None
    with open(json_file, "r", encoding="utf-8") as fp:
        data = json.load(fp)
    return str(data["supiOrSuci"])


def _emit_conceal_prints(
    imsi: str,
    suci_obj: Optional[Any],
    scheme_id: int,
    hn_privkey: Optional[bytes],
    hn_pubkey: Optional[bytes],
    suci_string: str,
) -> None:
    print(f"\n####################SUPI###############\n{imsi}")

    if scheme_id in (1, 2) and suci_obj is not None:
        print(f"\n####################SUCI###############\n{suci_obj}")

    if scheme_id in (1, 2):
        if hn_privkey:
            print(f"\n#################PRIVATE KEY###########\n{hn_privkey.hex()}")
        if hn_pubkey is not None:
            print(f"\n#################PUBLIC KEY############\n{hn_pubkey.hex()}")

    print(f"\n############SUCI STRING################\n{suci_string}")


def _emit_deconceal(dec_imsi: Optional[str]) -> None:
    print(f"\n##########DECONCEALED SUPI#############\n{dec_imsi}")


def generate_suci(
    scheme_id: Optional[int],
    hn_pubkey: Optional[bytes],
    hn_privkey: Optional[bytes],
    imsi: str,
    supi: Any,
    routing_indicator: str,
    key_id: int,
    plmn: str,
    msin: str,
    supi_type: str,
    json_file: Optional[str],
    verbose: bool = True,
) -> ConcealResult:
    suci_obj: Optional[Any] = None
    suci_string: str

    if scheme_id == 0:
        suci_string = f"suci-{supi_type}-{plmn[:3]}-{plmn[3:5]}-{routing_indicator}-{scheme_id}-0-{msin}"

    elif scheme_id == 1:
        ue_ecies = ECIES_UE(profile="A")
        ue_ecies.generate_sharedkey(hn_pubkey)
        ue_pubkey, ue_encmsin, ue_mac = ue_ecies.protect(supi["Value"]["Output"].to_bytes())
        suci_obj = FGSIDSUPI(
            val={
                "Fmt": FGSIDFMT_IMSI,
                "Value": {
                    "PLMN": f"{plmn}",
                    "ProtSchemeID": int(scheme_id),
                    "Output": {
                        "ECCEphemPK": ue_pubkey,
                        "CipherText": ue_encmsin,
                        "MAC": ue_mac,
                    },
                },
            }
        )
        ue_key_text = binascii.hexlify(ue_pubkey).decode().upper()
        enc_msin_text = binascii.hexlify(ue_encmsin).decode().upper()
        mac_text = binascii.hexlify(ue_mac).decode().upper()
        suci_string = (
            f"suci-{supi_type}-{plmn[:3]}-{plmn[3:6]}-{routing_indicator}-{scheme_id}-{key_id}-"
            f"{ue_key_text}{enc_msin_text}{mac_text}"
        )

    elif scheme_id == 2:
        ue_ecies = ECIES_UE(profile="B")
        ue_ecies.generate_sharedkey(hn_pubkey)
        ue_pubkey, ue_encmsin, ue_mac = ue_ecies.protect(supi["Value"]["Output"].to_bytes())
        suci_obj = FGSIDSUPI(
            val={
                "Fmt": FGSIDFMT_IMSI,
                "Value": {
                    "PLMN": f"{plmn}",
                    "ProtSchemeID": int(scheme_id),
                    "Output": {
                        "ECCEphemPK": ue_pubkey,
                        "CipherText": ue_encmsin,
                        "MAC": ue_mac,
                    },
                },
            }
        )
        ue_key_text = binascii.hexlify(ue_pubkey).decode().upper()
        enc_msin_text = binascii.hexlify(ue_encmsin).decode().upper()
        mac_text = binascii.hexlify(ue_mac).decode().upper()
        suci_string = (
            f"suci-{supi_type}-{plmn[:3]}-{plmn[3:6]}-{routing_indicator}-{scheme_id}-{key_id}-"
            f"{ue_key_text}{enc_msin_text}{mac_text}"
        )
    else:
        raise ValueError(f"Unsupported scheme_id: {scheme_id}")

    net_string = f"5G:mnc{plmn[3:6]}.mcc{plmn[:3]}.3gppnetwork.org"
    create_suci_json(json_file, suci_string, net_string)

    if verbose:
        _emit_conceal_prints(imsi, suci_obj, scheme_id or 0, hn_privkey, hn_pubkey, suci_string)

    pub_hex = hn_pubkey.hex() if hn_pubkey else None
    priv_hex = hn_privkey.hex() if hn_privkey else None
    return ConcealResult(
        imsi=imsi,
        suci_obj=suci_obj,
        suci_string=suci_string,
        net_string=net_string,
        hn_pubkey_hex=pub_hex,
        hn_privkey_hex=priv_hex,
    )


def _emit_parsed_suci_verbose(
    scheme_id: int,
    suci_obj: Any,
    hn_privkey: Optional[bytes],
    hn_pubkey: Optional[bytes],
    suci_string: str,
) -> None:
    """Match legacy CLI output when rebuilding SUCI from string (deconceal path)."""
    if scheme_id not in (1, 2):
        print(f"\n############SUCI STRING################\n{suci_string}")
        return
    print(f"\n####################SUCI###############\n{suci_obj}")
    if hn_privkey:
        print(f"\n#################PRIVATE KEY###########\n{hn_privkey.hex()}")
    if hn_pubkey is not None:
        print(f"\n#################PUBLIC KEY############\n{hn_pubkey.hex()}")
    print(f"\n############SUCI STRING################\n{suci_string}")


def parse_suci_string_to_fgsidsupi(
    suci_str: str,
    hn_pubkey: Optional[bytes],
    hn_privkey: Optional[bytes],
    json_file: Optional[str],
    verbose: bool = True,
) -> Tuple[Any, str, str]:
    """Parse SUCI string into FGSIDSUPI. Returns (suci_obj, suci_string, net_string). scheme_id 0 returns (None, ...)."""
    parts = suci_str.split("-")
    if len(parts) < 8 or parts[0] != "suci":
        raise ValueError("SUCI string must start with 'suci-' and contain all hyphen-separated fields.")

    supi_type = parts[1]
    suci_mcc = parts[2]
    suci_mnc = parts[3]
    routing_indicator = parts[4]
    scheme_id = int(parts[5])
    key_id = int(parts[6])
    pscheme_output = parts[7]
    plmn = str(suci_mcc) + str(suci_mnc)

    suci_obj: Optional[Any] = None

    if scheme_id == 0:
        msin_clear = pscheme_output
        suci_string = (
            f"suci-{supi_type}-{plmn[:3]}-{plmn[3:5]}-{routing_indicator}-{scheme_id}-0-{msin_clear}"
        )
        net_string = f"5G:mnc{plmn[3:6]}.mcc{plmn[:3]}.3gppnetwork.org"
        create_suci_json(json_file, suci_string, net_string)
        if verbose:
            print(f"\n############SUCI STRING################\n{suci_string}")
        return None, suci_string, net_string

    if scheme_id == 1:
        try:
            ue_ecies = ECIES_UE(profile="A")
            ue_pubkey = bytes.fromhex(str(pscheme_output[:64]).strip())
            ue_encmsin = bytes.fromhex(str(pscheme_output[64:74]).strip())
            ue_mac = bytes.fromhex(str(pscheme_output[74:]).strip())
        except ValueError as ex:
            raise ValueError(f"Invalid SUCI string (Profile A hex fields): {ex}") from ex
        if hn_pubkey is not None:
            ue_ecies.generate_sharedkey(hn_pubkey)
        suci_obj = FGSIDSUPI(
            val={
                "Fmt": FGSIDFMT_IMSI,
                "Value": {
                    "PLMN": f"{plmn}",
                    "ProtSchemeID": int(scheme_id),
                    "Output": {
                        "ECCEphemPK": ue_pubkey,
                        "CipherText": ue_encmsin,
                        "MAC": ue_mac,
                    },
                },
            }
        )
        ue_key_text = binascii.hexlify(ue_pubkey).decode().upper()
        enc_msin_text = binascii.hexlify(ue_encmsin).decode().upper()
        mac_text = binascii.hexlify(ue_mac).decode().upper()

    elif scheme_id == 2:
        try:
            ue_ecies = ECIES_UE(profile="B")
            ue_pubkey = bytes.fromhex(str(pscheme_output[:66]).strip())
            ue_encmsin = bytes.fromhex(str(pscheme_output[66:76]).strip())
            ue_mac = bytes.fromhex(str(pscheme_output[76:]).strip())
        except ValueError as ex:
            raise ValueError(f"Invalid SUCI string (Profile B hex fields): {ex}") from ex
        if hn_pubkey is not None:
            ue_ecies.generate_sharedkey(hn_pubkey)
        suci_obj = FGSIDSUPI(
            val={
                "Fmt": FGSIDFMT_IMSI,
                "Value": {
                    "PLMN": f"{plmn}",
                    "ProtSchemeID": int(scheme_id),
                    "Output": {
                        "ECCEphemPK": ue_pubkey,
                        "CipherText": ue_encmsin,
                        "MAC": ue_mac,
                    },
                },
            }
        )
        ue_key_text = binascii.hexlify(ue_pubkey).decode().upper()
        enc_msin_text = binascii.hexlify(ue_encmsin).decode().upper()
        mac_text = binascii.hexlify(ue_mac).decode().upper()
    else:
        raise ValueError(f"Unsupported scheme_id in SUCI string: {scheme_id}")

    suci_string = (
        f"suci-{supi_type}-{plmn[:3]}-{plmn[3:6]}-{routing_indicator}-{scheme_id}-{key_id}-"
        f"{ue_key_text}{enc_msin_text}{mac_text}"
    )
    net_string = f"5G:mnc{plmn[3:6]}.mcc{plmn[:3]}.3gppnetwork.org"
    create_suci_json(json_file, suci_string, net_string)

    if verbose and suci_obj is not None:
        _emit_parsed_suci_verbose(scheme_id, suci_obj, hn_privkey, hn_pubkey, suci_string)

    return suci_obj, suci_string, net_string


def decode_suci(
    scheme_id: Optional[int],
    hn_privkey: Optional[bytes],
    suci: Optional[Any],
    verbose: bool = True,
) -> Optional[str]:
    if scheme_id == 0 or suci is None:
        return None
    if hn_privkey is None:
        raise ValueError("Private key is required for deconceal when scheme_id is 1 or 2.")

    if scheme_id == 1:
        hn_ecies = ECIES_HN(hn_privkey, profile="A")
    elif scheme_id == 2:
        hn_ecies = ECIES_HN(hn_privkey, profile="B")
    else:
        return None

    rx_suci = FGSIDSUPI()
    rx_suci.from_bytes(suci.to_bytes())

    dec_msin = hn_ecies.unprotect(
        rx_suci["Value"]["Output"]["ECCEphemPK"].get_val(),
        rx_suci["Value"]["Output"]["CipherText"].get_val(),
        rx_suci["Value"]["Output"]["MAC"].get_val(),
    )

    try:
        dec_imsi = suci["Value"]["PLMN"].decode() + decode_bcd(dec_msin)
    except Exception:
        dec_imsi = "***Deconcealing error!***"

    if verbose:
        _emit_deconceal(dec_imsi)
    return dec_imsi


def load_private_key(
    scheme_id: Optional[int],
    private_key_file: str,
) -> Tuple[Optional[bytes], Optional[bytes]]:
    if scheme_id not in (1, 2):
        return None, None

    with open(str(private_key_file), "rb") as key_file:
        key_data = key_file.read()
    private_key = serialization.load_pem_private_key(key_data, password=None)

    if scheme_id == 1:
        hn_privkey = private_key.private_bytes_raw()
        hn_pubkey = private_key.public_key().public_bytes_raw()
        return hn_privkey, hn_pubkey

    if scheme_id == 2:
        ec = ECDH_SECP256R1()
        ec.PrivKey = private_key
        hn_pubkey = bytes(ec.get_pubkey())
        hn_privkey = bytes(ec.get_privkey())
        return hn_privkey, hn_pubkey

    return None, None


def load_public_key(scheme_id: Optional[int], public_key_file: str) -> Optional[bytes]:
    if scheme_id not in (1, 2):
        return None

    with open(str(public_key_file), "rb") as key_file:
        key_data = key_file.read()
    public_key = serialization.load_pem_public_key(key_data)

    if scheme_id == 1:
        return public_key.public_bytes_raw()

    if scheme_id == 2:
        der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return der[26:]

    return None


def generate_profile_a_keypair(
    keys_dir: Path | str,
    private_filename: str = "curve25519.pem",
    public_filename: str = "curve25519_pub.pem",
) -> Tuple[Path, Path]:
    """
    Create Profile A (X25519) PEM keys compatible with conceal/deconceal (same role as README OpenSSL commands).
    Pure Python via cryptography; works on Linux and Windows without the openssl CLI.
    """
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric import x25519

    d = Path(keys_dir).expanduser().resolve()
    d.mkdir(parents=True, exist_ok=True)

    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()

    priv_pem = priv.private_bytes(
        encoding=ser.Encoding.PEM,
        format=ser.PrivateFormat.PKCS8,
        encryption_algorithm=ser.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=ser.Encoding.PEM,
        format=ser.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path = d / private_filename
    pub_path = d / public_filename
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)
    try:
        priv_path.chmod(0o600)
    except (NotImplementedError, OSError):
        pass
    return priv_path, pub_path


def generate_profile_b_keypair(
    keys_dir: Path | str,
    private_filename: str = "secp256r1.pem",
    public_filename: str = "secp256r1_pub.pem",
) -> Tuple[Path, Path]:
    """
    Create Profile B (secp256r1 / P-256) PEM keys compatible with conceal/deconceal (README Profile B).
    """
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric import ec

    d = Path(keys_dir).expanduser().resolve()
    d.mkdir(parents=True, exist_ok=True)

    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()

    priv_pem = priv.private_bytes(
        encoding=ser.Encoding.PEM,
        format=ser.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=ser.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=ser.Encoding.PEM,
        format=ser.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path = d / private_filename
    pub_path = d / public_filename
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)
    try:
        priv_path.chmod(0o600)
    except (NotImplementedError, OSError):
        pass
    return priv_path, pub_path


def run_conceal(
    supi_type: str,
    routing_indicator: str,
    scheme_id: int,
    key_id: int,
    plmn: str,
    msin: str,
    private_key_file: Optional[str],
    public_key_file: Optional[str],
    json_file: Optional[str],
    verbose: bool = True,
) -> ConcealResult:
    _load_crypto_dependencies()
    imsi = f"{plmn}{msin}"
    supi = FGSIDSUPI(val={"Fmt": FGSIDFMT_IMSI, "Value": {"PLMN": plmn, "Output": msin}})

    hn_privkey: Optional[bytes] = None
    hn_pubkey: Optional[bytes] = None

    if scheme_id in (1, 2):
        if private_key_file:
            hn_privkey, hn_pubkey = load_private_key(scheme_id, private_key_file)
        elif public_key_file:
            hn_pubkey = load_public_key(scheme_id, public_key_file)
        else:
            raise ValueError("Provide --private_key_file or --public_key_file for scheme_id 1 or 2.")

    return generate_suci(
        scheme_id=scheme_id,
        hn_pubkey=hn_pubkey,
        hn_privkey=hn_privkey,
        imsi=imsi,
        supi=supi,
        routing_indicator=routing_indicator,
        key_id=key_id,
        plmn=plmn,
        msin=msin,
        supi_type=supi_type,
        json_file=json_file,
        verbose=verbose,
    )


def run_deconceal(
    suci_string: Optional[str],
    json_input_file: Optional[str],
    private_key_file: str,
    verbose: bool = True,
) -> DeconcealResult:
    _load_crypto_dependencies()
    if suci_string and json_input_file:
        raise ValueError("Use either SUCI string or JSON file, not both.")
    if not suci_string and not json_input_file:
        raise ValueError("Provide SUCI string or JSON file.")

    if json_input_file:
        loaded = get_suci_from_json(json_input_file)
        if loaded is None:
            raise FileNotFoundError(f"JSON file not found or invalid: {json_input_file}")
        suci_str = loaded
    else:
        suci_str = suci_string or ""

    prot_scheme_id = int(suci_str.split("-")[5])

    hn_privkey, hn_pubkey = load_private_key(prot_scheme_id, private_key_file)

    suci_obj, _, _ = parse_suci_string_to_fgsidsupi(
        suci_str,
        hn_pubkey=hn_pubkey,
        hn_privkey=hn_privkey,
        json_file=json_input_file,
        verbose=verbose,
    )

    dec_imsi = decode_suci(prot_scheme_id, hn_privkey, suci_obj, verbose=verbose)
    return DeconcealResult(dec_imsi=dec_imsi, suci_obj=suci_obj, scheme_id=prot_scheme_id)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="5G SUPI/SUCI conceal and deconceal (Profiles A/B, null scheme). "
        "Run with no arguments to open the GUI."
    )
    parser.add_argument(
        "--setup-env",
        action="store_true",
        help="Create/update ./env and install dependencies (PyCrates, CryptoMobile, requirements.txt), then exit.",
    )
    parser.add_argument(
        "--reinstall-git",
        action="store_true",
        help="With --setup-env: force reinstall PyCrates + CryptoMobile from GitHub.",
    )
    parser.add_argument(
        "--full-clone",
        action="store_true",
        help="With --setup-env: full git clones instead of shallow (--depth 1).",
    )
    parser.add_argument(
        "--no-bootstrap",
        action="store_true",
        help="Do not auto-create env/ or install missing dependencies (fail if imports are missing).",
    )
    parser.add_argument("--gui", action="store_true", help="Open graphical interface (same as running with no arguments).")
    parser.add_argument(
        "--gen-keys",
        metavar="PROFILE",
        choices=("profile_a", "profile_b", "a", "b"),
        default=None,
        help="Generate HN key PEMs in --keys-dir: profile_a|a = X25519 (Curve25519); profile_b|b = secp256r1 (P-256). Then exit.",
    )
    parser.add_argument(
        "--keys-dir",
        type=str,
        default="keys",
        help="Output directory for --gen-keys (created if missing). Default: keys",
    )
    parser.add_argument("--conceal", action="store_true", help="Conceal SUPI to SUCI.")
    parser.add_argument("--deconceal", action="store_true", help="Deconceal SUCI to SUPI.")
    parser.add_argument("--supi_type", type=str, required=False, help="SUPI type: 0 = IMSI, 1 = NAI.")
    parser.add_argument("--routing_indicator", type=str, required=False, help="Routing indicator, e.g. 0000.")
    parser.add_argument(
        "--scheme_id",
        type=int,
        required=False,
        choices=[0, 1, 2],
        help="0 = null-scheme, 1 = Profile A (Curve25519), 2 = Profile B (secp256r1).",
    )
    parser.add_argument("--key_id", type=int, required=False, help="Key ID.")
    parser.add_argument("--plmn", type=str, required=False, help="PLMN, e.g. 72417.")
    parser.add_argument("--msin", type=str, required=False, help="MSIN, e.g. 0000000001.")
    parser.add_argument("--private_key_file", type=str, required=False, help="HN private key PEM.")
    parser.add_argument("--public_key_file", type=str, required=False, help="HN public key PEM.")
    parser.add_argument("--suci_string", type=str, required=False, help="SUCI string for deconceal.")
    parser.add_argument(
        "--json_file",
        type=str,
        required=False,
        help="JSON with supiOrSuci (deconceal input) or output path for conceal.",
    )
    return parser



def run_gui() -> None:
    """Launch CustomTkinter UI (imports customtkinter on demand)."""
    import traceback
    import tkinter as tk
    from tkinter import filedialog, messagebox

    import customtkinter as ctk

    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")

    def _bind_mousewheel_to_textbox(widget: ctk.CTkTextbox) -> None:
        """CTkTextbox often misses Linux wheel; bind on the inner Tk Text only to avoid double-scroll."""
        inner = getattr(widget, "_textbox", None)
        if inner is None:
            return

        def scroll_units(delta: int) -> None:
            inner.yview_scroll(delta, "units")

        def on_mousewheel(event: tk.Event) -> str | None:
            if getattr(event, "delta", 0):
                scroll_units(int(-1 * (event.delta / 120)))
                return "break"
            return None

        def on_linux_up(_: tk.Event) -> str:
            scroll_units(-1)
            return "break"

        def on_linux_down(_: tk.Event) -> str:
            scroll_units(1)
            return "break"

        inner.bind("<MouseWheel>", on_mousewheel, add="+")
        inner.bind("<Button-4>", on_linux_up, add="+")
        inner.bind("<Button-5>", on_linux_down, add="+")
        # Wheel events go to the widget under the cursor; cover the CTk chrome too.
        widget.bind("<MouseWheel>", on_mousewheel, add="+")
        widget.bind("<Button-4>", on_linux_up, add="+")
        widget.bind("<Button-5>", on_linux_down, add="+")


    def _copy_all(app: ctk.CTk, widget: ctk.CTkTextbox) -> None:
        text = widget.get("1.0", "end-1c").strip()
        if not text:
            return
        app.clipboard_clear()
        app.clipboard_append(text)
        app.update()


    class SuciApp(ctk.CTk):
        def __init__(self) -> None:
            super().__init__()
            self.title("5G SUPI / SUCI Tool")
            # Default size fits all inputs without inner scroll; result panes share remaining height.
            self.geometry("980x640")
            self.minsize(880, 580)

            self.grid_columnconfigure(0, weight=1)
            self.grid_rowconfigure(1, weight=1)

            header = ctk.CTkFrame(self, fg_color="transparent")
            header.grid(row=0, column=0, sticky="ew", padx=20, pady=(12, 4))
            header.grid_columnconfigure(0, weight=1)

            ctk.CTkLabel(header, text="SUPI ⇄ SUCI", font=ctk.CTkFont(size=20, weight="bold")).grid(row=0, column=0, sticky="w")
            ctk.CTkLabel(
                header,
                text="Null scheme, Profile A (Curve25519), Profile B (secp256r1).",
                font=ctk.CTkFont(size=12),
                text_color=("gray30", "gray70"),
            ).grid(row=1, column=0, sticky="w", pady=(2, 0))

            self.tabs = ctk.CTkTabview(self)
            self.tabs.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 10))
            self.tabs.add("Conceal")
            self.tabs.add("Deconceal")
            self.tabs.add("Keys")

            self._build_conceal_tab()
            self._build_deconceal_tab()
            self._build_keys_tab()

            footer = ctk.CTkFrame(self, fg_color="transparent")
            footer.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 10))
            ctk.CTkLabel(
                footer,
                text="Same logic as suci_tool.py · PEM keys per README.",
                font=ctk.CTkFont(size=10),
                text_color=("gray40", "gray60"),
            ).pack(side="left")

        def _browse_open(self, var: tk.StringVar) -> None:
            path = filedialog.askopenfilename(parent=self)
            if path:
                var.set(path)

        def _browse_save_json(self, var: tk.StringVar) -> None:
            path = filedialog.asksaveasfilename(
                parent=self,
                defaultextension=".json",
                filetypes=[("JSON", "*.json"), ("All files", "*.*")],
            )
            if path:
                var.set(path)

        def _build_conceal_tab(self) -> None:
            tab = self.tabs.tab("Conceal")
            tab.grid_columnconfigure(0, weight=1)
            tab.grid_rowconfigure(0, weight=0)
            tab.grid_rowconfigure(2, weight=1)

            # Plain frame (no CTkScrollableFrame): avoids broken wheel routing and fits default height.
            form = ctk.CTkFrame(tab, fg_color="transparent")
            form.grid(row=0, column=0, sticky="ew", pady=(0, 4))
            form.grid_columnconfigure(1, weight=1)
            form.grid_columnconfigure(3, weight=1)

            self.cv_supi_type = tk.StringVar(value="0")
            self.cv_routing = tk.StringVar(value="0000")
            self.cv_scheme = tk.StringVar(value="1")
            self.cv_key_id = tk.StringVar(value="1")
            self.cv_plmn = tk.StringVar(value="72417")
            self.cv_msin = tk.StringVar(value="0000000001")
            self.cv_pub = tk.StringVar()
            self.cv_priv = tk.StringVar()
            self.cv_json_out = tk.StringVar()

            def lbl(c: int, r: int, text: str) -> None:
                ctk.CTkLabel(form, text=text, width=118, anchor="e", font=ctk.CTkFont(size=12)).grid(
                    row=r, column=c, padx=(0, 6), pady=3, sticky="e"
                )

            r = 0
            lbl(0, r, "SUPI type")
            ctk.CTkOptionMenu(form, variable=self.cv_supi_type, values=["0", "1"], width=100, height=30).grid(
                row=r, column=1, sticky="w", padx=(0, 12), pady=3
            )
            lbl(2, r, "Scheme")
            ctk.CTkOptionMenu(form, variable=self.cv_scheme, values=["0", "1", "2"], width=150, height=30).grid(row=r, column=3, sticky="ew", pady=3)
            r += 1

            lbl(0, r, "Routing ind.")
            ctk.CTkEntry(form, textvariable=self.cv_routing, placeholder_text="0000", height=30).grid(
                row=r, column=1, sticky="ew", padx=(0, 12), pady=3
            )
            lbl(2, r, "Key ID")
            ctk.CTkEntry(form, textvariable=self.cv_key_id, placeholder_text="1", height=30).grid(row=r, column=3, sticky="ew", pady=3)
            r += 1

            lbl(0, r, "PLMN")
            ctk.CTkEntry(form, textvariable=self.cv_plmn, placeholder_text="72417", height=30).grid(
                row=r, column=1, sticky="ew", padx=(0, 12), pady=3
            )
            lbl(2, r, "MSIN")
            ctk.CTkEntry(form, textvariable=self.cv_msin, placeholder_text="0000000001", height=30).grid(row=r, column=3, sticky="ew", pady=3)
            r += 1

            ctk.CTkLabel(
                form,
                text="0 = null · 1 = Profile A (X25519) · 2 = Profile B (P-256)",
                font=ctk.CTkFont(size=10),
                text_color=("gray40", "gray60"),
                anchor="w",
            ).grid(row=r, column=0, columnspan=4, sticky="w", pady=(0, 4))
            r += 1

            lbl(0, r, "Public key")
            pub_row = ctk.CTkFrame(form, fg_color="transparent")
            pub_row.grid_columnconfigure(0, weight=1)
            pub_row.grid(row=r, column=1, columnspan=3, sticky="ew", pady=3)
            ctk.CTkEntry(pub_row, textvariable=self.cv_pub, placeholder_text="PEM path (scheme 1 or 2)", height=30).grid(row=0, column=0, sticky="ew")
            ctk.CTkButton(pub_row, text="Browse…", width=88, height=30, command=lambda: self._browse_open(self.cv_pub)).grid(
                row=0, column=1, padx=(6, 0)
            )
            r += 1

            lbl(0, r, "Private key")
            priv_row = ctk.CTkFrame(form, fg_color="transparent")
            priv_row.grid_columnconfigure(0, weight=1)
            priv_row.grid(row=r, column=1, columnspan=3, sticky="ew", pady=3)
            ctk.CTkEntry(priv_row, textvariable=self.cv_priv, placeholder_text="Optional PEM (derive public for conceal)", height=30).grid(
                row=0, column=0, sticky="ew"
            )
            ctk.CTkButton(priv_row, text="Browse…", width=88, height=30, command=lambda: self._browse_open(self.cv_priv)).grid(
                row=0, column=1, padx=(6, 0)
            )
            r += 1

            lbl(0, r, "JSON out")
            json_row = ctk.CTkFrame(form, fg_color="transparent")
            json_row.grid_columnconfigure(0, weight=1)
            json_row.grid(row=r, column=1, columnspan=3, sticky="ew", pady=3)
            ctk.CTkEntry(json_row, textvariable=self.cv_json_out, placeholder_text="Optional supiOrSuci JSON path", height=30).grid(
                row=0, column=0, sticky="ew"
            )
            ctk.CTkButton(json_row, text="Save…", width=88, height=30, command=lambda: self._browse_save_json(self.cv_json_out)).grid(
                row=0, column=1, padx=(6, 0)
            )

            btn_bar = ctk.CTkFrame(tab, fg_color="transparent")
            btn_bar.grid(row=1, column=0, sticky="ew", pady=(4, 4))
            ctk.CTkButton(
                btn_bar,
                text="Run conceal",
                command=self._on_conceal,
                height=32,
                font=ctk.CTkFont(size=13, weight="bold"),
            ).pack(side="left")

            out_frame = ctk.CTkFrame(tab)
            out_frame.grid(row=2, column=0, sticky="nsew", pady=(4, 0))
            out_frame.grid_columnconfigure(0, weight=1)
            out_frame.grid_rowconfigure(1, weight=1)

            top_out = ctk.CTkFrame(out_frame, fg_color="transparent")
            top_out.grid(row=0, column=0, sticky="ew", padx=10, pady=(8, 4))
            ctk.CTkLabel(top_out, text="Result", font=ctk.CTkFont(size=12, weight="bold")).pack(side="left")
            self.conceal_out = ctk.CTkTextbox(out_frame, font=ctk.CTkFont(family="Consolas", size=11))
            self.conceal_out.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 8))
            ctk.CTkButton(top_out, text="Copy all", width=88, height=28, command=lambda: _copy_all(self, self.conceal_out)).pack(side="right")
            _bind_mousewheel_to_textbox(self.conceal_out)

        def _on_conceal(self) -> None:
            self.conceal_out.delete("1.0", "end")
            try:
                supi_type = self.cv_supi_type.get().strip()
                routing = self.cv_routing.get().strip()
                scheme_id = int(self.cv_scheme.get())
                key_id = int(self.cv_key_id.get().strip())
                plmn = self.cv_plmn.get().strip()
                msin = self.cv_msin.get().strip()
                pub = self.cv_pub.get().strip() or None
                priv = self.cv_priv.get().strip() or None
                jf = self.cv_json_out.get().strip() or None

                if scheme_id in (1, 2) and not pub and not priv:
                    messagebox.showwarning("Missing key", "Provide a public or private key PEM for Profile A or B.")
                    return

                res: ConcealResult = run_conceal(
                    supi_type=supi_type,
                    routing_indicator=routing,
                    scheme_id=scheme_id,
                    key_id=key_id,
                    plmn=plmn,
                    msin=msin,
                    private_key_file=priv,
                    public_key_file=pub,
                    json_file=jf,
                    verbose=False,
                )
                lines = [
                    "SUPI (IMSI)",
                    res.imsi,
                    "",
                    "SUCI string",
                    res.suci_string,
                    "",
                    "Serving network name",
                    res.net_string,
                ]
                if res.hn_pubkey_hex:
                    lines += ["", "Home network public key (hex)", res.hn_pubkey_hex]
                if res.hn_privkey_hex:
                    lines += ["", "Home network private key (hex)", res.hn_privkey_hex]
                if res.suci_obj is not None:
                    lines += ["", "SUCI (structured)", str(res.suci_obj)]
                self.conceal_out.insert("1.0", "\n".join(lines))
            except Exception:
                self.conceal_out.insert("1.0", traceback.format_exc())

        def _build_deconceal_tab(self) -> None:
            tab = self.tabs.tab("Deconceal")
            tab.grid_columnconfigure(0, weight=1)
            tab.grid_rowconfigure(1, weight=0)
            tab.grid_rowconfigure(3, weight=1)

            mode = ctk.CTkFrame(tab, fg_color="transparent")
            mode.grid(row=0, column=0, sticky="ew", pady=(0, 4))
            self.dv_mode = tk.StringVar(value="string")
            ctk.CTkRadioButton(mode, text="SUCI string", variable=self.dv_mode, value="string", command=self._toggle_deconceal_mode).pack(
                side="left", padx=(0, 14)
            )
            ctk.CTkRadioButton(mode, text="JSON (supiOrSuci)", variable=self.dv_mode, value="json", command=self._toggle_deconceal_mode).pack(
                side="left"
            )

            form = ctk.CTkFrame(tab, fg_color="transparent")
            form.grid(row=1, column=0, sticky="ew", pady=(0, 4))
            form.grid_columnconfigure(1, weight=1)

            ctk.CTkLabel(form, text="SUCI string", width=118, anchor="e", font=ctk.CTkFont(size=12)).grid(
                row=0, column=0, sticky="ne", padx=(0, 6), pady=3
            )
            self.dv_suci = ctk.CTkTextbox(form, height=70, font=ctk.CTkFont(family="Consolas", size=11))
            self.dv_suci.grid(row=0, column=1, sticky="ew", pady=3)
            _bind_mousewheel_to_textbox(self.dv_suci)

            ctk.CTkLabel(form, text="JSON file", width=118, anchor="e", font=ctk.CTkFont(size=12)).grid(
                row=1, column=0, sticky="e", padx=(0, 6), pady=3
            )
            json_inner = ctk.CTkFrame(form, fg_color="transparent")
            json_inner.grid_columnconfigure(0, weight=1)
            json_inner.grid(row=1, column=1, sticky="ew", pady=3)
            self.dv_json = tk.StringVar()
            self.dv_json_entry = ctk.CTkEntry(
                json_inner, textvariable=self.dv_json, placeholder_text="Path to JSON with supiOrSuci", height=30
            )
            self.dv_json_entry.grid(row=0, column=0, sticky="ew")
            self.dv_json_btn = ctk.CTkButton(json_inner, text="Browse…", width=88, height=30, command=lambda: self._browse_open(self.dv_json))
            self.dv_json_btn.grid(row=0, column=1, padx=(6, 0))

            ctk.CTkLabel(form, text="Private key", width=118, anchor="e", font=ctk.CTkFont(size=12)).grid(
                row=2, column=0, sticky="e", padx=(0, 6), pady=3
            )
            priv_inner = ctk.CTkFrame(form, fg_color="transparent")
            priv_inner.grid_columnconfigure(0, weight=1)
            priv_inner.grid(row=2, column=1, sticky="ew", pady=3)
            self.dv_priv = tk.StringVar()
            ctk.CTkEntry(priv_inner, textvariable=self.dv_priv, placeholder_text="Home network private key PEM", height=30).grid(
                row=0, column=0, sticky="ew"
            )
            ctk.CTkButton(priv_inner, text="Browse…", width=88, height=30, command=lambda: self._browse_open(self.dv_priv)).grid(
                row=0, column=1, padx=(6, 0)
            )

            self._toggle_deconceal_mode()

            btn_bar = ctk.CTkFrame(tab, fg_color="transparent")
            btn_bar.grid(row=2, column=0, sticky="ew", pady=(4, 4))
            ctk.CTkButton(
                btn_bar,
                text="Run deconceal",
                command=self._on_deconceal,
                height=32,
                font=ctk.CTkFont(size=13, weight="bold"),
            ).pack(side="left")

            out_frame = ctk.CTkFrame(tab)
            out_frame.grid(row=3, column=0, sticky="nsew", pady=(4, 0))
            out_frame.grid_columnconfigure(0, weight=1)
            out_frame.grid_rowconfigure(1, weight=1)

            top_out = ctk.CTkFrame(out_frame, fg_color="transparent")
            top_out.grid(row=0, column=0, sticky="ew", padx=10, pady=(8, 4))
            ctk.CTkLabel(top_out, text="Result", font=ctk.CTkFont(size=12, weight="bold")).pack(side="left")
            self.deconceal_out = ctk.CTkTextbox(out_frame, font=ctk.CTkFont(family="Consolas", size=11))
            self.deconceal_out.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 8))
            ctk.CTkButton(top_out, text="Copy all", width=88, height=28, command=lambda: _copy_all(self, self.deconceal_out)).pack(side="right")
            _bind_mousewheel_to_textbox(self.deconceal_out)

        def _toggle_deconceal_mode(self) -> None:
            use_json = self.dv_mode.get() == "json"
            self.dv_suci.configure(state=("disabled" if use_json else "normal"))
            self.dv_json_entry.configure(state=("normal" if use_json else "disabled"))
            self.dv_json_btn.configure(state=("normal" if use_json else "disabled"))

        def _on_deconceal(self) -> None:
            self.deconceal_out.delete("1.0", "end")
            try:
                priv = self.dv_priv.get().strip()
                if not priv:
                    messagebox.showwarning("Missing key", "Select the home network private key PEM.")
                    return
                suci_str = None
                json_path = None
                if self.dv_mode.get() == "string":
                    suci_str = self.dv_suci.get("1.0", "end-1c").strip()
                    if not suci_str:
                        messagebox.showwarning("Missing SUCI", "Paste or enter the SUCI string.")
                        return
                else:
                    json_path = self.dv_json.get().strip()
                    if not json_path:
                        messagebox.showwarning("Missing JSON", "Choose the JSON file with supiOrSuci.")
                        return

                res: DeconcealResult = run_deconceal(
                    suci_string=suci_str,
                    json_input_file=json_path,
                    private_key_file=priv,
                    verbose=False,
                )
                lines = [
                    "Scheme ID",
                    str(res.scheme_id),
                    "",
                    "Deconcealed SUPI (IMSI)",
                    res.dec_imsi if res.dec_imsi is not None else "(null scheme — MSIN is not encrypted)",
                ]
                if res.suci_obj is not None:
                    lines += ["", "SUCI (structured)", str(res.suci_obj)]
                self.deconceal_out.insert("1.0", "\n".join(lines))
            except Exception:
                self.deconceal_out.insert("1.0", traceback.format_exc())

        def _browse_keys_dir(self) -> None:
            path = filedialog.askdirectory(parent=self)
            if path:
                self.kv_dir.set(path)

        def _build_keys_tab(self) -> None:
            tab = self.tabs.tab("Keys")
            tab.grid_columnconfigure(0, weight=1)

            hint = ctk.CTkLabel(
                tab,
                text="Generate home-network PEM keys with cryptography (no openssl CLI). Same profiles as README.",
                font=ctk.CTkFont(size=12),
                text_color=("gray30", "gray70"),
                anchor="w",
            )
            hint.grid(row=0, column=0, sticky="ew", pady=(0, 8))

            self.kv_dir = tk.StringVar(value=str(Path.cwd() / "keys"))

            row = ctk.CTkFrame(tab, fg_color="transparent")
            row.grid(row=1, column=0, sticky="ew", pady=4)
            row.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(row, text="Output folder", width=120, anchor="w").grid(row=0, column=0, padx=(0, 8))
            ctk.CTkEntry(row, textvariable=self.kv_dir, height=30).grid(row=0, column=1, sticky="ew")
            ctk.CTkButton(row, text="Browse…", width=96, height=30, command=self._browse_keys_dir).grid(row=0, column=2, padx=(8, 0))

            self.kv_profile = tk.StringVar(value="profile_a")
            seg = ctk.CTkSegmentedButton(
                tab,
                values=["Profile A (X25519)", "Profile B (P-256)"],
                command=self._on_keys_profile_segment,
            )
            seg.grid(row=2, column=0, sticky="w", pady=12)
            seg.set("Profile A (X25519)")
            self._keys_seg = seg

            btn_bar = ctk.CTkFrame(tab, fg_color="transparent")
            btn_bar.grid(row=3, column=0, sticky="ew", pady=8)
            ctk.CTkButton(
                btn_bar,
                text="Generate keys",
                command=self._on_generate_keys,
                height=34,
                font=ctk.CTkFont(size=13, weight="bold"),
            ).pack(side="left")

            self.keys_out = ctk.CTkTextbox(tab, height=120, font=ctk.CTkFont(family="Consolas", size=11))
            self.keys_out.grid(row=4, column=0, sticky="nsew", pady=(8, 0))
            tab.grid_rowconfigure(4, weight=1)
            _bind_mousewheel_to_textbox(self.keys_out)

        def _on_keys_profile_segment(self, value: str) -> None:
            if value.startswith("Profile A"):
                self.kv_profile.set("profile_a")
            else:
                self.kv_profile.set("profile_b")

        def _on_generate_keys(self) -> None:
            self.keys_out.delete("1.0", "end")
            try:
                d = Path(self.kv_dir.get().strip()).expanduser()
                if self.kv_profile.get() == "profile_a":
                    priv, pub = generate_profile_a_keypair(d)
                    label = "Profile A (X25519)"
                else:
                    priv, pub = generate_profile_b_keypair(d)
                    label = "Profile B (secp256r1 / P-256)"
                msg = f"{label}\n\nPrivate:\n{priv}\n\nPublic:\n{pub}\n"
                self.keys_out.insert("1.0", msg)
            except Exception:
                self.keys_out.insert("1.0", traceback.format_exc())
                messagebox.showerror("Generate keys failed", "See the Keys tab output for details.")



    app = SuciApp()
    app.mainloop()


def _gui_dependencies_importable() -> bool:
    try:
        import customtkinter  # noqa: F401
        return True
    except ModuleNotFoundError:
        return False


def _run_gui_application() -> int:
    """
    Launch the GUI. If the current interpreter lacks customtkinter (typical with system Python),
    run the same bootstrap as crypto deps, then re-exec under ./env so requirements.txt applies.
    """
    if not _gui_dependencies_importable():
        if not _allow_auto_bootstrap():
            print(
                "GUI requires customtkinter. Install it in this environment, or run without "
                "SUCI_TOOL_NO_BOOTSTRAP / --no-bootstrap so the tool can create ./env:\n"
                f'  "{sys.executable}" "{Path(__file__).resolve()}" --setup-env',
                file=sys.stderr,
            )
            return 1
        try:
            bootstrap_environment(reinstall_git=False, shallow_clone=True)
        except (RuntimeError, subprocess.CalledProcessError) as e:
            print(f"Could not install GUI dependencies: {e}", file=sys.stderr)
            return 1

        env_py = _venv_python()
        if env_py.exists() and Path(sys.executable).resolve() != env_py.resolve():
            script = _script_path_for_relaunch()
            rc = subprocess.call([str(env_py), str(script)] + list(sys.argv[1:]))
            raise SystemExit(rc)

        if not _gui_dependencies_importable():
            print(
                "customtkinter is still missing. Install it (e.g. pip install customtkinter) "
                "or run with the ./env interpreter after --setup-env.",
                file=sys.stderr,
            )
            return 1

    run_gui()
    return 0


def main_cli(argv: Optional[list[str]] = None) -> int:
    if argv is None:
        argv_rest = _consume_own_script_argv(list(sys.argv[1:]))
    else:
        argv_rest = list(argv)

    if len(argv_rest) == 0:
        return _run_gui_application()

    parser = build_arg_parser()
    args = parser.parse_args(argv_rest)

    if args.no_bootstrap:
        os.environ["SUCI_TOOL_NO_BOOTSTRAP"] = "1"

    if args.setup_env:
        if args.gui or args.conceal or args.deconceal or args.gen_keys:
            parser.error("--setup-env cannot be combined with --gui, --conceal, --deconceal, or --gen-keys.")
        try:
            bootstrap_environment(reinstall_git=args.reinstall_git, shallow_clone=not args.full_clone)
        except (RuntimeError, subprocess.CalledProcessError) as e:
            print(str(e), file=sys.stderr)
            return 1
        return 0

    if args.reinstall_git or args.full_clone:
        parser.error("--reinstall-git and --full-clone require --setup-env.")

    if args.gui:
        return _run_gui_application()

    if args.gen_keys:
        if args.conceal or args.deconceal:
            parser.error("--gen-keys cannot be combined with --conceal or --deconceal.")
        keys_dir = Path(args.keys_dir).expanduser().resolve()
        try:
            if args.gen_keys in ("profile_a", "a"):
                priv_path, pub_path = generate_profile_a_keypair(keys_dir)
            else:
                priv_path, pub_path = generate_profile_b_keypair(keys_dir)
        except Exception as e:
            print(str(e), file=sys.stderr)
            return 1
        print(f"Private key written: {priv_path}")
        print(f"Public key written:  {pub_path}")
        return 0

    if args.conceal and args.deconceal:
        parser.error("--conceal and --deconceal cannot be used together.")

    if args.conceal:
        if args.supi_type is None:
            parser.error("--supi_type is required with --conceal.")
        if args.routing_indicator is None:
            parser.error("--routing_indicator is required with --conceal.")
        if args.scheme_id is None:
            parser.error("--scheme_id is required with --conceal.")
        if args.key_id is None:
            parser.error("--key_id is required with --conceal.")
        if args.plmn is None:
            parser.error("--plmn is required with --conceal.")
        if args.msin is None:
            parser.error("--msin is required with --conceal.")
        if args.scheme_id in (1, 2) and not args.private_key_file and not args.public_key_file:
            parser.error("--private_key_file or --public_key_file required for scheme_id 1 or 2 with --conceal.")

    elif args.deconceal:
        if not args.suci_string and not args.json_file:
            parser.error("--json_file or --suci_string required with --deconceal.")
        if args.suci_string and args.json_file:
            parser.error("--json_file and --suci_string cannot be used together with --deconceal.")
        if args.supi_type:
            parser.error("--supi_type is not supported with --deconceal.")
        if args.routing_indicator:
            parser.error("--routing_indicator is not supported with --deconceal.")
        if args.scheme_id is not None:
            parser.error("--scheme_id is not supported with --deconceal.")
        if args.key_id is not None:
            parser.error("--key_id is not supported with --deconceal.")
        if args.plmn:
            parser.error("--plmn is not supported with --deconceal.")
        if args.msin:
            parser.error("--msin is not supported with --deconceal.")
        if args.public_key_file:
            parser.error("--public_key_file is not supported with --deconceal.")
        if args.private_key_file is None:
            parser.error("--private_key_file is required with --deconceal.")
    else:
        parser.error(
            "Use --conceal, --deconceal, --gui, --gen-keys, or --setup-env "
            "(or run with no arguments for the GUI)."
        )

    try:
        if args.conceal:
            run_conceal(
                supi_type=args.supi_type,
                routing_indicator=args.routing_indicator,
                scheme_id=args.scheme_id,
                key_id=args.key_id,
                plmn=args.plmn,
                msin=args.msin,
                private_key_file=args.private_key_file,
                public_key_file=args.public_key_file,
                json_file=args.json_file,
                verbose=True,
            )
        else:
            run_deconceal(
                suci_string=args.suci_string,
                json_input_file=args.json_file,
                private_key_file=args.private_key_file,
                verbose=True,
            )
    except (ValueError, FileNotFoundError) as e:
        print(str(e), file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main_cli())
