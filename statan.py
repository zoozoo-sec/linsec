
import magic
import hashlib
import json
import urllib.request, urllib.error, urllib.parse
import urllib.request, urllib.parse, urllib.error
import sys
import os
import yara
import subprocess
import requests


class Static:

    def __init__(self, mal_file):
        self.file = mal_file
        self.md5 = ""

    def filetype(self):
        if os.path.exists(self.file):
            try:
                m = magic.open(magic.MAGIC_NONE)
                m.load()
                ftype = m.file(self.file)
                return ftype
            except AttributeError:
                ftype = magic.from_file(self.file)
                return ftype    
        else:
            print("No such file or directory:", self.file)
            sys.exit()

    def get_file_size(self):
        fr = open(self.file, 'rb')
        size = len(fr.read())
        fr.close()
        return size

    def md5sum(self):
        if os.path.exists(self.file):
            f = open(self.file, 'rb')
            m = hashlib.md5(f.read())
            self.md5 = m.hexdigest()
            return self.md5
        else:
            print("No such file or directory:", self.file)
            sys.exit()

    def yararules(self, rulesfile):
        rules = yara.compile(rulesfile)
        matches = rules.match(self.file)
        return matches

    def virustotal(self, key):
        url = "https://www.virustotal.com/api/get_file_report.json"
        md5 = self.md5
        parameters = {'resource' : md5, "key" : key}
        encoded_parameters = urllib.parse.urlencode(parameters).encode("utf-8")
        try:
            request = urllib.request.Request(url, encoded_parameters)
            response = urllib.request.urlopen(request)
            json_obj = response.read()
            json_obj_dict = json.loads(json_obj)
            if json_obj_dict['result'] ==0:
                print("\t  " + "No match found for " + self.md5)
            else:
                avresults = json_obj_dict['report'][1]
                return avresults

        except urllib.error.URLError as error:
            print("Cannot get results from Virustotal: " + str(error))

    def ssdeep(self):
        fhash = subprocess.check_output(["ssdeep", self.file])
        splitted = fhash.split(b"\n")
        return splitted[1]

    def ssdeep_compare(self, master_ssdeep_file):
        output = subprocess.check_output(["ssdeep", "-m", master_ssdeep_file, self.file])
        return output

    def ascii_strings(self):
        output = subprocess.check_output(["strings", "-a", self.file])
        return output

    def unicode_strings(self):
        output = subprocess.check_output(["strings", "-a", "-el", self.file])
        return output

    def dependencies(self):
        try:
            output = subprocess.check_output(["ldd", self.file])
            return output
        except:
            pass

    def elf_header(self):
        output = subprocess.check_output(["readelf","-h",self.file])
        return output

    def program_header(self):
        output = subprocess.check_output(["readelf","-l",self.file])
        return output

    def section_header(self):
        output = subprocess.check_output(["readelf","-S",self.file])
        return output

    def symbols(self):
        output = subprocess.check_output(["readelf","-s",self.file])
        return output


    def upload_file_to_virustotal(self,file_path, api_key):
        url = "https://www.virustotal.com/api/v3/files"
        headers = {
            "accept": "application/json",
            "X-Apikey": api_key
        }
        with open(file_path, "rb") as file:
            files = {"file": file}
            response = requests.post(url, headers=headers, files=files)

        if response.status_code == 200:
            response_data = response.json()
            analysis_id = response_data["data"]["id"]
            print(f"File uploaded successfully. Analysis ID: {analysis_id}")
            return analysis_id
        else:
            print(f"Error uploading file: {response.status_code} - {response.text}")
            return None


    def get_analysis_results(self,analysis_id, api_key):
        url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        headers = {
            "accept": "application/json",
            "X-Apikey": api_key
        }
        response = requests.get(url, headers=headers)

        if response.status_code == 200:return response.json()
        else:
            print(f"Error fetching analysis results: {response.status_code} - {response.text}")
            return None
    def parse_av_results(self, data):
        import time;time.sleep(2)
        listed = []
        try:
            results = data["data"]["attributes"]["results"]
            for av_name, details in results.items():                
                if details["category"] not in ["undetected", "type-unsupported","failure"]:
                    listed.append(f"AV Name: {av_name}, detects the file as  {details["category"]}")
            return listed
        except KeyError as e:
            print(f"Key error: {e}")