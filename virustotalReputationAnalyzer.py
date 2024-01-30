import os
import json
import hashlib
import requests

# You will need to obtain an API Key from VirusTotal
API_KEY = '4c7bb0cea973baa1759946dde19d2b8b2899bb20ade21ab2a5f041ab19c766fc'

#Path to folder and report name
TARGET_FOLDER = '/Users/rickyvillareal/Desktop/School/2023/Fall 2023/CYBV 473/Week 14/TARGET'
REPORT_FILE = 'vt_report.txt'

#Open file path to read files
def calculate_md5(file_path):
    with open(file_path, 'rb') as f:
        md5_hash = hashlib.md5(f.read()).hexdigest()
    return md5_hash

#Access virustotal.com with API key
def submit_to_virustotal(md5_hash):
    url = f'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': API_KEY, 'resource': md5_hash}
    response = requests.get(url, params=params)
    result = response.json()
    return result

#Opens and will eventually write to .txt report
def save_report(file_path, content):
    with open(file_path, 'w') as f:
        f.write(content)

#Goes through every file in TARGET folder and saves to report
def process_files_in_folder(folder_path):
    report_content = ""
    
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            md5_hash = calculate_md5(file_path)
            response = submit_to_virustotal(md5_hash)
            
            report_content += f"File: {file_path}\n"
            report_content += json.dumps(response, sort_keys=False, indent=4) + "\n"
            report_content += "="*30 + "\n\n"

    save_report(REPORT_FILE, report_content)

if __name__ == "__main__":
    process_files_in_folder(TARGET_FOLDER)
    print(f"Report generated and saved to {REPORT_FILE}")
