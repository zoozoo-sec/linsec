import google.generativeai as genai
import json
import re
import sys
from datetime import *
import time
genai.configure(api_key="AIzaSyADrq-OA_DK_OCYf5t6FC-ufAgziaYIzbI")
model = genai.GenerativeModel("gemini-1.5-flash", generation_config={
    "temperature": 0.2,
    "top_p": 0.3, 
    "max_output_tokens": 512 
})



def extract_json(text):
    """Extracts JSON from a given text response using regex."""
    match = re.search(r'\{.*\}', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            return {"error": "Invalid JSON format received"}
    return {"error": "No JSON found"}


def danger_check(reportfile):  
    with open(reportfile,'r') as f:
        data = f.read()
        f.close()
        pattern = r'"maliciousness_score"\s*:\s*"?(\d+)"?'
        matches = re.findall(pattern, data)
        print(matches)
        average_score = sum(list(map(int, matches)))/2
        print(average_score)
        if average_score > 6.5: 
            print("danger")
            sys.exit(111)
        else: 
            print("benign")
            sys.exit(222)


def static_analyze_malware(filename,filepath):
    timeis = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    report_template = {
    "static_analysis": {
            "filepath":filepath,
            "filename": "",
            "md5": "",
            "file_type": "",
            "size": "15.98 KB",
            "virustotal_detections": {
            },
            "maliciousness_score": "",
            "rating_justification": "",
            "packer_detected": "",
            "yara_matches": ""
        }
    }
    strings_template = {
        "strings_analysis":{
            "suspicious_strings": [],
            "maliciousness_score": 1,
            "justification": "",
            "potential_threats": ""
        }
}
    report_prompt = f"""
    You are a malware analysis AI. Given an ASCII report from a Linux automated malware analysis tool (NOT JSON), generate a valid JSON response in this format:

    {json.dumps(report_template, indent=4)}

    **Instructions:**
    - Ensure output is strictly valid JSON with `{{}}` brackets.
    - **Maliciousness score (1-10)** 1 being benign and 10 being highly danger
    - Do NOT include explanations or markdown formatting like ` ```json `.
    - Start with `{{` and end with `}}`.
    - If a value is `null`, enclose it in quotes for JSON compatibility.
    - If VirusTotal detections are high, classify malware type (e.g., "Trojan", "Rootkit","keylogger","spyware").

    **File Info:**
    - Filename: {filename}
    - Filepath: {filepath}

    Now, analyze the following report:
    """

    strings_prompt = f"""
    You are a malware analysis AI. Given a report from a Linux automated malware analysis tool, return a JSON response  following this format:

    {json.dumps(strings_template, indent=4)}

    Instructions:
    - **List of suspicious strings (if any)**
    - **Maliciousness score (1-10)**
    - **Justification for the score**
    - **Brief insights on potential threats**
    - **If input has errors, adjust with corrected json type
    - **DONT OPEN THE JSON DATA WITH OPEN FLOWER BRACKET BECAUSE THIS JSON NEEDS TO BE ADDED TO ANOTHER JSON SO JUST END WITH CLOSE BEACKET AND DONT START WITH ANY!!!

    Ensure output is a **valid JSON** only. 


    Here are the extracted strings:

            THE FILE NAME IS {filename} and the PATH TO FILE IS {filepath}

    """

    try:
        with open(f'root/linux_reports/{filename}/final_report.txt', 'r') as report_file:
            report_content = report_file.read()
        report_response = model.generate_content(report_prompt + report_content)
        report_result = extract_json(report_response.text)
        print("\n=== Report Analysis ===\n", json.dumps(report_result, indent=4))

        with open(f'root/linux_reports/{filename}/strings_ascii.txt', 'r') as strings_file:
            strings_content = strings_file.read()
        strings_response = model.generate_content(strings_prompt + strings_content)
        strings_result = extract_json(strings_response.text)
        print("\n=== Strings Analysis ===\n", json.dumps(strings_result, indent=4))
        with open(f"root/linux_reports/{filename}/static_report.json",'w') as f:
            raw  = (json.dumps(report_result, indent=4))[:-2]
            raw += ','
            f.write(raw)
            f.write((json.dumps(strings_result, indent=4))[1:])
            f.close()
        with open(f"root/linux_reports/{filename}/static_report.json",'r') as a:
            data = json.load(a)
            data["static_analysis"]["timestamp"] = timeis
            a.close()
            with open(f"root/linux_reports/{filename}/static_report.json", "w") as file:
                json.dump(data, file, indent=4)
        danger_check(f"root/linux_reports/{filename}/static_report.json")
    except FileNotFoundError as e:
        print(f"Error: {e}")


def dyanamic_analyze_malware(filename,filepath):
    try:
        with open(f'root/linux_reports/{filename}/final_report.txt', 'r') as log_file:
            report_content = log_file.read()

        # Unified prompt with the full report
        unified_prompt = f"""
        Analyze the dynamic execution report of a binary and return a structured JSON object with the following details: IMPORTANT: DONT EVER THROW ERROR LIKE UNVALID JSON ERROS. JUST ADJUST AS NEEDED!!

        2. **DNS Analysis**:
           - List of suspicious domain lookups (if any)
           - Maliciousness score (1-10)
           - Justification for the score
           - Brief insights on potential threats

        3. **TCP Analysis**:
           - List of suspicious IPs/domains (if any)
           - Maliciousness score (1-10)
           - Justification for the score
           - Brief insights on potential threats

           **If your json key or value hash value 'null' enclose it in quotes to satisify json standards

        Ensure the output is a **valid JSON** structured as:
        {{
          "dns_analysis": {'{}'},
          "tcp_analysis": {'{}'}
        }}

        ### **Dynamic Execution Report:**
        THE FILE NAME IS {filename} and the PATH TO FILE IS {filepath}
        {report_content}
        """
        response = model.generate_content(unified_prompt)
        result = extract_json(response.text)

        print(json.dumps(result, indent=4))
        with open(f"root/linux_reports/{filename}/dyanamic_report.json",'w') as f:
            f.write(json.dumps(result, indent=4))
            f.close()

        danger_check(f"root/linux_reports/{filename}/dyanamic_report.json")

    except FileNotFoundError as e:
        print(f"Error: {e}")



if __name__  == "__main__":
    args = sys.argv[1:] 
    print(args)
    if len(args) > 0:
        if args[0] == '1':
            static_analyze_malware(args[1],args[2])
        elif args[0] == '2':
            dyanamic_analyze_malware(args[1])
    else:
        print("INVALID ARGUMENTS")