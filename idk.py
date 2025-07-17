# -*- coding: utf-8 -*-
# Combined keyboxer and check functionality with source display for valid keyboxes

import hashlib
import os
from pathlib import Path
import re
import time
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv
from lxml import etree
import lxml.etree as ET
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding

# --- check.py content start ---

url = "https://android.googleapis.com/attestation/status"
headers = {
    "Cache-Control": "max-age=0, no-cache, no-store, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
}

params = {"ts": int(time.time())}

response = requests.get(url, headers=headers, params=params)
if response.status_code != 200:
    raise Exception(f"Error fetching data: {response.reason}")
status_json = response.json()


def parse_number_of_certificates(xml_string):
    root = ET.fromstring(xml_string)

    number_of_certificates = root.find(".//NumberOfCertificates")

    if number_of_certificates is not None and number_of_certificates.text is not None:
        count = int(number_of_certificates.text.strip())
        return count
    else:
        raise Exception("No NumberOfCertificates found.")


def parse_certificates(xml_string, pem_number):
    root = ET.fromstring(xml_string)

    pem_certificates = root.findall('.//Certificate[@format="pem"]')

    if pem_certificates is not None:
        pem_contents = [cert.text.strip() if cert.text is not None else '' for cert in pem_certificates[:pem_number]]
        return pem_contents
    else:
        raise Exception("No Certificate found.")


def parse_private_key(xml_string):
    root = ET.fromstring(xml_string)

    private_key = root.find(".//PrivateKey")
    if private_key is not None and private_key.text is not None:
        return private_key.text.strip()
    else:
        raise Exception("No PrivateKey found.")


def load_public_key_from_file(file_path):
    with open(file_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
    return public_key


def compare_keys(public_key1, public_key2):
    return public_key1.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    ) == public_key2.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def keybox_check(certificate_text):
    try:
        pem_number = parse_number_of_certificates(certificate_text)
        pem_certificates = parse_certificates(certificate_text, pem_number)
        private_key = parse_private_key(certificate_text)
    except Exception as e:
        print(f"[Keybox Check Error]: {e}")
        return False

    try:
        certificate = x509.load_pem_x509_certificate(pem_certificates[0].encode(), default_backend())
        try:
            private_key = re.sub(re.compile(r"^\s+", re.MULTILINE), "", private_key)
            private_key = serialization.load_pem_private_key(
                private_key.encode(), password=None, backend=default_backend()
            )
            check_private_key = True
        except Exception:
            check_private_key = False
    except Exception as e:
        print(f"[Keybox Check Error]: {e}")
        return False

    # Certificate Validity Verification
    serial_number = certificate.serial_number
    serial_number_string = hex(serial_number)[2:].lower()
    not_valid_before = certificate.not_valid_before_utc
    not_valid_after = certificate.not_valid_after_utc
    current_time = datetime.now(timezone.utc)
    is_valid = not_valid_before <= current_time <= not_valid_after
    if not is_valid:
        return False

    # Private Key Verification
    if check_private_key:
        private_key_public_key = private_key.public_key()
        certificate_public_key = certificate.public_key()
        if not compare_keys(private_key_public_key, certificate_public_key):
            return False
    else:
        return False

    # Keychain Authentication
    for i in range(pem_number - 1):
        son_certificate = x509.load_pem_x509_certificate(pem_certificates[i].encode(), default_backend())
        father_certificate = x509.load_pem_x509_certificate(pem_certificates[i + 1].encode(), default_backend())

        if son_certificate.issuer != father_certificate.subject:
            return False
        signature = son_certificate.signature
        signature_algorithm = son_certificate.signature_algorithm_oid._name
        tbs_certificate = son_certificate.tbs_certificate_bytes
        public_key = father_certificate.public_key()
        try:
            if signature_algorithm in [
                "sha256WithRSAEncryption",
                "sha1WithRSAEncryption",
                "sha384WithRSAEncryption",
                "sha512WithRSAEncryption",
            ]:
                hash_algorithm = {
                    "sha256WithRSAEncryption": hashes.SHA256(),
                    "sha1WithRSAEncryption": hashes.SHA1(),
                    "sha384WithRSAEncryption": hashes.SHA384(),
                    "sha512WithRSAEncryption": hashes.SHA512(),
                }[signature_algorithm]
                padding_algorithm = padding.PKCS1v15()
                public_key.verify(signature, tbs_certificate, padding_algorithm, hash_algorithm)
            elif signature_algorithm in [
                "ecdsa-with-SHA256",
                "ecdsa-with-SHA1",
                "ecdsa-with-SHA384",
                "ecdsa-with-SHA512",
            ]:
                hash_algorithm = {
                    "ecdsa-with-SHA256": hashes.SHA256(),
                    "ecdsa-with-SHA1": hashes.SHA1(),
                    "ecdsa-with-SHA384": hashes.SHA384(),
                    "ecdsa-with-SHA512": hashes.SHA512(),
                }[signature_algorithm]
                padding_algorithm = ec.ECDSA(hash_algorithm)
                public_key.verify(signature, tbs_certificate, padding_algorithm)
            else:
                raise ValueError("Unsupported signature algorithms")
        except Exception:
            return False

    # Root Certificate Validation
    root_certificate = x509.load_pem_x509_certificate(pem_certificates[-1].encode(), default_backend())
    root_public_key = root_certificate.public_key()
    google_public_key = load_public_key_from_file("pem/google.pem")
    aosp_ec_public_key = load_public_key_from_file("pem/aosp_ec.pem")
    aosp_rsa_public_key = load_public_key_from_file("pem/aosp_rsa.pem")
    knox_public_key = load_public_key_from_file("pem/knox.pem")
    if compare_keys(root_public_key, google_public_key):
        pass
    elif compare_keys(root_public_key, aosp_ec_public_key):
        return False
    elif compare_keys(root_public_key, aosp_rsa_public_key):
        return False
    elif compare_keys(root_public_key, knox_public_key):
        print("Found a knox key !?")
    else:
        return False

    # Number of Certificates in Keychain
    if pem_number >= 4:
        return False

    status = None
    for i in range(pem_number):
        certificate = x509.load_pem_x509_certificate(pem_certificates[i].encode(), default_backend())
        serial_number = certificate.serial_number
        serial_number_string = hex(serial_number)[2:].lower()
        if status_json["entries"].get(serial_number_string, None):
            status = status_json["entries"][serial_number_string]
            break
    if status is not None:
        return False

    return True

# --- check.py content end ---

# --- keyboxer.py content start ---

session = requests.Session()

# Load environment variables from .env file
load_dotenv()
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

if not GITHUB_TOKEN:
    raise ValueError("GITHUB_TOKEN is not set in the .env file")

# Search query
search_query = "<AndroidAttestation>"
search_url = f"https://api.github.com/search/code?q={search_query}"

# Headers for the API request
headers = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json",
}

save = Path(__file__).resolve().parent / "keys"
cache_file = Path(__file__).resolve().parent / "cache.txt"
if cache_file.exists():
    cached_urls = set(open(cache_file, "r").readlines())
else:
    cached_urls = set()


# Function to fetch and print search results
def fetch_and_process_results(page: int) -> bool:
    params = {"per_page": 100, "page": page}
    response = session.get(search_url, headers=headers, params=params)
    if response.status_code != 200:
        raise RuntimeError(f"Failed to retrieve search results: {response.status_code}")
    search_results = response.json()
    if "items" in search_results:
        for item in search_results["items"]:
            file_name = item["name"]
            # Process only XML files
            if file_name.lower().endswith(".xml"):
                raw_url: str = (
                    item["html_url"].replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                )
                # check if the file exists in cache
                if raw_url + "\n" in cached_urls:
                    continue
                else:
                    cached_urls.add(raw_url + "\n")
                # Fetch the file content
                file_content = fetch_file_content(raw_url)
                # Parse the XML
                try:
                    root = etree.fromstring(file_content)
                except etree.XMLSyntaxError:
                    continue
                # Get the canonical form (C14N)
                canonical_xml = etree.tostring(root, method="c14n")
                # Hash the canonical XML
                hash_value = hashlib.sha256(canonical_xml).hexdigest()
                file_name_save = save / (hash_value + ".xml")
                if not file_name_save.exists() and file_content and keybox_check(file_content):
                    print(f"{raw_url} is new and valid")
                    with open(file_name_save, "wb") as f:
                        f.write(file_content)
    return len(search_results["items"]) > 0  # Return True if there could be more results


# Function to fetch file content
def fetch_file_content(url: str) -> bytes:
    response = session.get(url)
    if response.status_code == 200:
        return response.content
    else:
        raise RuntimeError(f"Failed to download {url}")


# Fetch all pages
page = 1
while fetch_and_process_results(page):
    page += 1

# update cache
open(cache_file, "w").writelines(cached_urls)

for file_path in save.glob("*.xml"):
    file_content = file_path.read_bytes()  # Read file content as bytes
    # Run CheckValid to determine if the file is still valid
    if keybox_check(file_content):
        print(f"Valid keybox found: {file_path.name} (from saved file)")
    else:
        # Prompt user for deletion
        user_input = input(f"File '{file_path.name}' is no longer valid. Do you want to delete it? (y/N): ")
        if user_input.lower() == "y":
            try:
                file_path.unlink()  # Delete the file
                print(f"Deleted file: {file_path.name}")
            except OSError as e:
                print(f"Error deleting file {file_path.name}: {e}")
        else:
            print(f"Kept file: {file_path.name}")

# --- keyboxer.py content end ---
