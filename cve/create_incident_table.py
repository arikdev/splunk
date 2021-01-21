import requests
import json
import sys
from datetime import datetime
from time import sleep
import splunklib.client as client
import splunklib.results as results
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators

HOST = "localhost"
PORT = 8089
USERNAME = "admin"
PASSWORD = "faurecia#security"

service = client.connect(
  host=HOST,
  port=PORT,
  username=USERNAME,
  password=PASSWORD)

index = 'cve'

def handle_cve(item, part, vendor, product, version, cves):
    cve_item = json.loads(item)
    cve = cve_item['cve']
    meta_data = cve['CVE_data_meta']
    cve_id = meta_data['ID']
    conf = cve_item['configurations']
    nodes = conf['nodes']
    found = False
    for node in nodes:
        if found:
            break;
        if 'cpe_match' not in node:
            continue
        matches = node['cpe_match']
        for match in matches:
            if found:
                break;
            cpe = match['cpe23Uri']
            tokens = cpe.split(':')
            cur_part = tokens[2]
            cur_vendor = tokens[3]
            cur_product = tokens[4]
            if cur_part != part or cur_vendor != vendor or cur_product != product:
                continue
            cur_version = tokens[5]
            if cur_version.find(version) != -1:
                print(">>>> Found direct version : " + cve_id + " " + cur_version)
                cves.append(cve_id)
                found = True
                continue
            if cur_version == '*':
                startIncluding = None
                endIncluding = None
                if 'versionStartIncluding' in match:
                    startIncluding = match['versionStartIncluding']
                    print('startIncluding:' + startIncluding)
                if 'versionEndIncluding' in match:
                    startIncluding = match['versionEndIncluding']
                    print('endIncluding:' + startIncluding + ' ' + cve_id)
                if startIncluding is None and endIncluding is None:
                    print(">>>> Found * version : " + cve_id + " " + cur_version)
                    cves.append(cve_id)
                    found = True

            #print(version + ' ' + cur_version)
            #if version == '-':
                #print(tokens)

    return cves

def get_cves(part, vendor, product, version):
    cves = []
    search = f'search index="' + index + '" | search configurations.nodes{}.cpe_match{}.cpe23Uri="cpe:2.3:%s:%s:%s:*"' % (part, vendor, product)
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
            handle_cve(item['_raw'], part, vendor, product, version, cves)

    return cves

cves = get_cves('o', 'linux', 'linux_kernel', '5.4')
print(cves)
