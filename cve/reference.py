from io import BytesIO
from zipfile import ZipFile
import requests
import json
import sys
import re

counter = 0
res = {}
files_found = 0

def handle_files(cve_id, files):
    global files_found
    for file in files:
        if cve_id not in res:
            res[cve_id] = []
        if file not in res[cve_id]:
            print('>>>>>>>>>>>>>>' + ' id:' + cve_id + ' ' + file)
            res[cve_id].append(file)
            files_found += 1

def handle_patch(cve_id, str_patch):
    global files_found
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
    #print('----------------------' + cve_id + ': ' + str(counter) + '--------------------------------------------------------')
    #print(url)
    try:
      response = requests.get(url)
    except:
      print('Eeception URL:' + url)
      return
    handle_patch(cve_id, str(response.content, 'utf-8'))

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
        handle_patch(cve_id, i['value'])


def handle_feed(data):
  for item in data["CVE_Items"]:
    #if files_found > 100:
        #break
    if 'cve' not in item:
        continue
    cve = item['cve']
    cve_meta_data = cve['CVE_data_meta']
    #print('============================================ : ' + cve_meta_data['ID'])
    handle_description(cve_meta_data['ID'], cve)
    if 'references' not in cve:
        continue
    references = cve['references']
    if 'reference_data' not in references:
        continue
    ref_data = references['reference_data']
    for r in ref_data:
      handle_ref(cve_meta_data['ID'], r)

f = open("cve_log.txt", "w")

suffixes = [
    "2020",
]

for suffix in suffixes:
    url = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%s.json.zip' % suffix
    response = requests.get(url)
    data = {}
    zipfile = ZipFile(BytesIO(response.content))

    for i in zipfile.namelist():
      if i == "nvdcve-1.1-%s.json" % suffix:
        data = json.loads(zipfile.read(i))
        break
    handle_feed(data)

print("RES:")
f.write("RES:\n")
print(res)
f.close()

with open('source_files.json', 'w') as f:
    json.dump(res, f)
