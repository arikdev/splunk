from __future__ import print_function
from io import BytesIO
from zipfile import ZipFile
import requests
import json
import sys
from datetime import datetime
from datetime import datetime
from time import sleep
import splunklib.client as client
import splunklib.results as results
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators

def cve_exists(cve_id):
  HOST = "localhost"
  PORT = 8089
  USERNAME = "admin"
  PASSWORD = "faurecia#security"

  service = client.connect(
      host=HOST,
      port=PORT,
      username=USERNAME,
      password=PASSWORD)

  search = 'search index="cve_arik" | search cve.CVE_data_meta.ID="' + cve_id + '"'
  job = service.jobs.create(search)
  while True:
    while not job.is_ready():
      pass
    if job['isDone'] == '1':
      break
    sleep(0.05)

  reader = results.ResultsReader(job.results())

  for item in reader:
    if '_raw' in item:
        return True

  return False

suffixes = [
    "modified",
]

f = open("cve_log.txt", "w")

for suffix in suffixes:
    url = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%s.json.zip' % suffix
    response = requests.get(url)
    data = {}
    zipfile = ZipFile(BytesIO(response.content)) 

    for i in zipfile.namelist():
        if i == "nvdcve-1.1-%s.json" % suffix:
            data = json.loads(zipfile.read(i))
            break

    for item in data["CVE_Items"]:
      if 'cve' in item:
          cve = item['cve']
          if 'CVE_data_meta' in cve:
              cve_meta_data = cve['CVE_data_meta']
              if 'ID' in cve_meta_data:
                  f.write("> checking CVE ID:" + cve_meta_data['ID'] + "\n")
                  if (cve_exists(cve_meta_data['ID']) == False):
                    f.write(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Insert CVE ID:" + cve_meta_data['ID'] + " NOT exists:\n")
                    print(json.dumps(item))
f.close()
