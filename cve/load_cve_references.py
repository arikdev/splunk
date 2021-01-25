from time import sleep
import splunklib.client as client
import splunklib.results as results
import requests
import json
import sys
import re

counter = 0
res = {}
files_found = 0

def handle_files(cve_id, files):
    global f
    global files_found
    for file in files:
        if cve_id not in res:
            info = {}
            info['files'] = []
            info['commits'] = []
            res[cve_id] = info
        if file not in res[cve_id]['files']:
            f.write('>>>>>FILE ' + cve_id + ' ' + file + '\n')
            res[cve_id]['files'].append(file)
            files_found += 1

def handle_commit(cve_id, url):
    tokens = url.split('/')
    commit_id = tokens[-1]
    tokens = commit_id.split('=')
    commit_id = tokens[-1]
    if cve_id not in res:
       info = {}
       info['files'] = []
       info['commits'] = []
       res[cve_id] = info
    if commit_id not in res[cve_id]['commits']:
        res[cve_id]['commits'].append(commit_id)
        f.write('>>>>>COMMIT ' + commit_id + ' from url: ' + url + '\n')


def handle_patch(cve_id, url, str_patch):
    global files_found
    if url is not None:
        handle_commit(cve_id, url)
    words = re.split('\s+', str_patch)
    for word in words:
        if '.c' in word or '.h' in word:
            files = re.findall(r'(/[a-zA-Z0-9\/]*\w+\.[ch])[^a-z]', word)
            handle_files(cve_id, files)


def handle_ref(cve_id, r):
    global counter
    if 'tags' not in r:
        return
    tags = r['tags']
    if 'Patch' not in tags:
       return
    if 'url' not in r:
       return
    url = r['url']
    if 'git' not in url:
        return
    if 'commit' not in url:
        return
    counter = counter + 1
    try:
      response = requests.get(url)
    except:
      f.write('Eeception URL:' + url + '\n')
      return
    handle_patch(cve_id, url, str(response.content, 'utf-8'))

def handle_description(cve_id, cve):
    if 'description' not in cve:
        return
    desc = cve['description']
    if 'description_data' not in desc:
        return;
    desc_data = desc['description_data']
    for i in desc_data:
        if 'value' not in i:
            continue
        handle_patch(cve_id, None, i['value'])


def handle_cve(data):
    item = json.loads(data)
    cve = item['cve']
    cve_meta_data = cve['CVE_data_meta']
    handle_description(cve_meta_data['ID'], cve)
    if 'references' not in cve:
        return
    references = cve['references']
    if 'reference_data' not in references:
        return
    ref_data = references['reference_data']
    for r in ref_data:
      handle_ref(cve_meta_data['ID'], r)

f = open("cve_reference_log.txt", "w")

HOST = "localhost"
PORT = 8089
USERNAME = "admin"
PASSWORD = "faurecia#security"

index = 'cve' 
service = client.connect(
  host=HOST,
  port=PORT,
  username=USERNAME,
  password=PASSWORD)

search = 'search index="' + index +'"'
job = service.jobs.create(search, max_count=4096)
while True:
    while not job.is_ready():
        pass
    if job['isDone'] == '1':
        break
    sleep(0.05)

kwargs_options = {"count" : 4096}
reader = results.ResultsReader(job.results(**kwargs_options))
for item in reader:
    if '_raw' in item:
        handle_cve(item['_raw'])

for cve_id, cve_info in res.items():
    cve_ref = {}
    cve_ref['cve_id'] = cve_id
    cve_ref['files'] = cve_info['files']
    if 'commits' in cve_info:
        cve_ref['commits'] = cve_info['commits']
    print(json.dumps(cve_ref))

f.write('FINISH!!!!\n')
f.close()
