from io import BytesIO
from zipfile import ZipFile
import requests
import json
import sys
import re

#url = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%s.json.zip' % '2020'
#response = requests.get(url)
#zipfile = ZipFile(BytesIO(response.content)) 

counter = 0
files_list = []

def handle_patch(patch):
    #lines = f.readlines();
    #data = ''.join(lines)
    print('--------------------  PATCH --------------------------------------------------------------------')
    print(type(patch))
    print(patch)
    str_patch = str(patch, 'utf-8')
    words = re.split('\s+', str_patch)
    for word in words:
        if '.c' in word:
           files = re.findall(r'(/[a-zA-Z0-9\/]*\w+\.c)[^a-z]', word)
           for file in files:
               print('>>>>>>>>>>>>>>' + file)
               files_list.append(file)

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
    print('----------------------' + cve_id + ': ' + str(counter) + '--------------------------------------------------------')
    print(url)
    response = requests.get(url)
    handle_patch(response.content)

def handle_feed(data):
  for item in data["CVE_Items"]:
    if 'cve' not in item:
        continue
    cve = item['cve']
    if 'references' not in cve: 
        continue
    references = cve['references']
    cve_meta_data = cve['CVE_data_meta']
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
    try:
      response = requests.get(url)
    except:
      print('Eeception URL:' + url)
    data = {}
    zipfile = ZipFile(BytesIO(response.content))

    for i in zipfile.namelist():
      if i == "nvdcve-1.1-%s.json" % suffix :
        data = json.loads(zipfile.read(i))
        break
    handle_feed(data)

f.close()

files_set = set(files_list)
print(files_set)
