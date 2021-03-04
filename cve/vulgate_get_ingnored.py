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

CSV_HOME = '/home/manage/splunk/etc/apps/lookup_editor/lookups/'
IGNORE_FILE = 'vul_cve_ignore.csv'

HOST = "localhost"
PORT = 8089
USERNAME = "admin"
PASSWORD = "faurecia#security"
index= 'vulgate'

service = client.connect(
  host=HOST,
  port=PORT,
  username=USERNAME,
  password=PASSWORD)


search = 'search index="' + index + '"'
job = service.jobs.create(search)
while True:
    while not job.is_ready():
        pass
    if job['isDone'] == '1':
        break
    sleep(0.05)

kwargs_options = {"count" : 1024}
reader = results.ResultsReader(job.results(**kwargs_options))
for item in reader:
    if '_raw' in item:
        data = json.loads(item['_raw'])
vulgateAuditReport = data['vulgateAuditReport']
print(vulgateAuditReport)
vulnerableCpes = vulgateAuditReport['vulnerableCpes']
print(len(vulnerableCpes))
userIgnoredCves = vulnerableCpes[0]['userIgnoredCves']
with open(CSV_HOME + IGNORE_FILE, 'w') as fp:
    for i in userIgnoredCves:
        print((i['cveId'], i['userJustificationForIgnoring']))
        fp.write(i['cveId']+','+ i['userJustificationForIgnoring'] + '\n')
