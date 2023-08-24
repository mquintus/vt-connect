import virustotal_python
from pprint import pprint
import argparse
import logging
import hashlib
import os

logging.basicConfig(level=logging.INFO)

parser = argparse.ArgumentParser(
    prog="VT-Connect.py",
    description="Connect to VirusTotal API. "
    + "Either check for a known file or upload an unknown file.",
    epilog="Enjoy the program! :)",
)
parser.add_argument(
    "-f",
    "--file",
    type=str,
    action="store",
    help="File to check against VirusTotal.",
)
parser.add_argument(
    "-u", "--upload", action="store_true", help="Upload file to VirusTotal."
)
args = parser.parse_args()

f = open("vault/vt.key", "r")
api_key = f.read().replace("\n", "")
logging.info(f"Using API key: {api_key}")
f.close()

FILE_PATH = args.file
logging.info(f"Using file: {FILE_PATH}")


if not args.upload:
    f = open(FILE_PATH, "rb")
    malware = f.read()
    FILE_HASH = hashlib.md5(malware).hexdigest()
    logging.info(f"Using file HASH: {FILE_HASH}")

    with virustotal_python.Virustotal(api_key) as vtotal:
        resp = vtotal.request(f"files/{FILE_HASH}")
        pprint(f"Reputation: {resp.data['attributes']['reputation']}")
        pprint(resp.data['attributes']['last_analysis_stats'])

else:
    # Create dictionary containing the file to send for multipart encoding upload
    files = {
        "file": (os.path.basename(FILE_PATH), open(os.path.abspath(FILE_PATH), "rb"))
    }

    with virustotal_python.Virustotal(api_key) as vtotal:
        resp = vtotal.request("files", files=files, method="POST")
        pprint(resp.json())
