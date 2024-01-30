# VirusTotal-File-Reputation-Analyzer

This repository contains a Python script for interacting with the VirusTotal API to assess the reputation of files within a specified folder. The script calculates the MD5 hash of each file, submits it to VirusTotal for analysis using an API key, and compiles the results into a detailed report.

## Key Components

1. **API Key:** The script requires a valid VirusTotal API key (`API_KEY`) for authentication. This key is used to submit file hashes for analysis.

2. **Target Folder:** The variable `TARGET_FOLDER` specifies the path to the folder containing the files to be analyzed. The script recursively processes all files in this folder and its subdirectories.

3. **Report File:** The variable `REPORT_FILE` indicates the name of the text file where the analysis results will be saved. The report includes information about each file's analysis results from VirusTotal.

4. **Functions:**
   - `calculate_md5(file_path)`: Computes the MD5 hash of a given file.
   - `submit_to_virustotal(md5_hash)`: Submits the MD5 hash to VirusTotal using their API and retrieves the analysis results.
   - `save_report(file_path, content)`: Saves the report content to a text file.
   - `process_files_in_folder(folder_path)`: Iterates through all files in the specified folder, calculates MD5 hashes, submits them to VirusTotal, and compiles the results into a report.

5. **Execution:** The script executes the `process_files_in_folder` function to analyze files in the specified target folder. The generated report is then saved to the file specified by `REPORT_FILE`, and a confirmation message is printed.

## Usage Instructions

1. Obtain a VirusTotal API key and replace the placeholder in the script (`API_KEY`) with the actual key.

2. Set the `TARGET_FOLDER` variable to the path of the folder containing the files you want to analyze.

3. Run the script. It will process each file in the target folder, submit the MD5 hash to VirusTotal, and generate a detailed report.

4. The report will be saved to the file specified by `REPORT_FILE`. Check the printed message for the location of the generated report.

**Note:** Make sure to comply with VirusTotal's terms of service and API usage policies while using this script.
