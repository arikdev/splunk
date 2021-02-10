import requests
import json
import sys
from datetime import datetime
from time import sleep
import splunklib.results as results
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
from time import time
from splunk_tools import search_splunk
from splunk_tools import connect_splunk

CSV_HOME = '/home/manage/splunk/etc/apps/lookup_editor/lookups/'
CPE_TABLE = 'vul_cpe.csv'
PRODUCT_TABLE = 'vul_product_table.csv'
PRODUCT_CPE_TABLE = 'vul_product_cpe.csv'
INCIDENT_TABLE = 'vul_incidents.csv'
CPE_COMPILED_FILES_TABLE = 'vul_cpe_compiled_files.csv'

HOST = "localhost"
PORT = 8089
USERNAME = "admin"
PASSWORD = "faurecia#security"


index = 'cve6'
ref_index = 'cve_ref6'

def handle_ref(item, cve):
    j = json.loads(item)
    if 'cve_id' not in j:
        return
    if cve not in j['cve_id']:
        return
    print('--- ' + j['cve_id'])
    if 'files' not in j:
        print('  No files')
    else:
        files = j['files']
        for f in files:
            print(f)


def handle_cve(item, cve, *argv):
    j = json.loads(item)
    show_url = False

    params = argv[0]
    if len(params) > 1:
        if params[1] == 'url':
            show_url = True


    if 'references' not in j['cve']:
        return

    refs = j['cve']['references']
    if 'reference_data' not in refs:
        return
    for ref in refs['reference_data']:
        if 'tags' not in ref:
            continue
        if 'Patch' not in ref['tags']:
            continue
        if show_url:
            if 'url' in ref:
                url = ref['url']
                print(url)

def handle_show_ref(argv):
    global service
    cve = argv[0]
    search = f'search index=' + ref_index
    search_splunk(service, search, 4096, handle_ref, cve)

def handle_show_cve(argv):
    global service
    cve = argv[0]

    search = f'search index=' + index + ' | search cve.CVE_data_meta.ID=' + cve 
    search_splunk(service, search, 4096, handle_cve, cve, argv)



if len(sys.argv) < 2:
    print('usage: ' + sys.argv[0] + ' [show_ref|show_cve]')
    sys.exit()

service = connect_splunk(
  host=HOST,
  port=PORT,
  username=USERNAME,
  password=PASSWORD)

if sys.argv[1] == 'show_ref':
    handle_show_ref(sys.argv[2:])
if sys.argv[1] == 'show_cve':
    handle_show_cve(sys.argv[2:])

