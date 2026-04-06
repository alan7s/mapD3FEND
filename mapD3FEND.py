import json
import pandas as pd
from tqdm import tqdm
import requests
import os

#Code adapted from https://github.com/Galeax/CVE2CAPEC by alan7s in 2026

TECHNIQUES_ENTERPRISE_FILE_URL = "https://attack.mitre.org/docs/attack-excel-files/v18.1/enterprise-attack/enterprise-attack-v18.1-techniques.xlsx"
ENTERPRISE_XSLX_CASE = 9
TECHNIQUES_MOBILE_FILE_URL = "https://attack.mitre.org/docs/attack-excel-files/v18.1/mobile-attack/mobile-attack-v18.1-techniques.xlsx"
MOBILE_XSLX_CASE = 10
TECHNIQUES_ICS_FILE_URL = "https://attack.mitre.org/docs/attack-excel-files/v18.1/ics-attack/ics-attack-v18.1-techniques.xlsx"
ICS_XSLX_CASE = 9
TECHNIQUES_FILE = "resources/techniques_db.json"
DEFENDE_SITE = 'https://d3fend.mitre.org/api/offensive-technique/attack/'

def load_techniques():
    try:
        with open(TECHNIQUES_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading the data: {str(e)}")
        return None

def update_defend_techniques():
    techniques = load_techniques()
    if techniques:
        file_path = f"resources/defend_db.jsonl"
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w') as f:
            for technique_id in tqdm(techniques, desc="Updating D3FEND techniques", unit="technique"):
                defend = {technique_id: []}
                response = requests.get(f"{DEFENDE_SITE}{technique_id}.json")
                if response.status_code == 200:
                    result = response.json()
                    for key in result.get("off_to_def").get("results").get("bindings"):
                        id = key.get("def_tech_id").get("value") if key.get("def_tech_id") else ""
                        tactic = key.get("def_tactic_label").get("value") if key.get("def_tactic_label") else ""
                        technique = key.get("def_tech_label").get("value") if key.get("def_tech_label") else ""
                        artifact = key.get("def_artifact_label").get("value") if key.get("def_artifact_label") else ""
                        entry = {"id": id, "tactic": tactic, "technique": technique, "artifact": artifact}
                        if id and tactic and technique and artifact and entry not in defend[technique_id]:
                            defend[technique_id].append(entry)
                f.write(json.dumps(defend) + '\n')

def download_techniques(base_url, case):
    try:
        data = pd.read_excel(base_url)
        result = {}
        for i in range(0, len(data)):
            result[data.iloc[i, 0]] = data.iloc[i, case].split(", ")
        return result
    except Exception as e:
        print(f"Error downloading the data: {str(e)}")
        return None


def save_json(data):
    os.makedirs(os.path.dirname(TECHNIQUES_FILE), exist_ok=True)
    with open(TECHNIQUES_FILE, 'w') as f:
        json.dump(data, f, indent=4)
    

if __name__ == "__main__":
    print("[!] Downloading techniques data...")
    techniques_data = download_techniques(TECHNIQUES_ENTERPRISE_FILE_URL, ENTERPRISE_XSLX_CASE)
    techniques_data.update(download_techniques(TECHNIQUES_MOBILE_FILE_URL, MOBILE_XSLX_CASE))
    techniques_data.update(download_techniques(TECHNIQUES_ICS_FILE_URL, ICS_XSLX_CASE))
    if techniques_data:
        print("[!] Saving techniques data...")
        save_json(techniques_data)
    update_defend_techniques()
    print("[+] D3FEND techniques updated successfully!")