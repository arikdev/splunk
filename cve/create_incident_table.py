import requests
import json
import sys
from datetime import datetime
from time import sleep
import splunklib.client as client
import splunklib.results as results
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
import csv_tools as csv

CSV_HOME = '/home/manage/splunk/etc/apps/lookup_editor/lookups/'
CPE_TABLE = 'vul_cpe.csv'
PRODUCT_TABLE = 'vul_product_table.csv'
PRODUCT_CPE_TABLE = 'vul_product_cpe.csv'
INCIDENT_TABLE = 'vul_incidents.csv'

HOST = "localhost"
PORT = 8089
USERNAME = "admin"
PASSWORD = "faurecia#security"

service = client.connect(
  host=HOST,
  port=PORT,
  username=USERNAME,
  password=PASSWORD)

index = 'cve3'

debug = False

def version_cmp(ver1, ver2):
    parts1 = [int(x) for x in ver1.split('.')]
    parts2 = [int(x) for x in ver2.split('.')]

    len_diff = len(parts1) - len(parts2)
    if len_diff > 0:
        for i in range(len_diff):
            parts2.append(0)
    if len_diff < 0:
        for i in range(-len_diff):
            parts1.append(0)

    for i in range(len(parts1)):
        if parts1[i] > parts2[i]:
            return 1
        if parts2[i] > parts1[i]:
            return -1

    return 0

def get_cvss(cve_item):
    cvss = '0'
    impact = cve_item['impact']
    if 'baseMetricV3' in impact:
        if 'cvssV3' in impact['baseMetricV3']:
            if 'baseScore' in impact['baseMetricV3']['cvssV3']:
                return  impact['baseMetricV3']['cvssV3']['baseScore']
    if 'baseMetricV2' in impact:
        if 'cvssV2' in impact['baseMetricV2']:
            if 'baseScore' in impact['baseMetricV2']['cvssV2']:
                return  impact['baseMetricV2']['cvssV2']['baseScore']

    return cvss

def handle_cve(item, part, vendor, product, version, cves):
    cve_item = json.loads(item)
    cve = cve_item['cve']
    meta_data = cve['CVE_data_meta']
    cve_id = meta_data['ID']
    conf = cve_item['configurations']
    nodes = conf['nodes']
    cvss = str(get_cvss(cve_item))
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
                cve_info = {}
                cve_info['cve_id'] = cve_id
                cve_info['cvss'] = cvss
                cves.append(cve_info)
                found = True
                break
            if cur_version == '-':
                print('----------------------------- cve:' + cve_id)
            if cur_version == '*':
                startIncluding = None
                endIncluding = None
                if 'versionStartIncluding' in match:
                    startIncluding = match['versionStartIncluding']
                    if version_cmp(version, startIncluding) == -1:
                        continue;
                if 'versionEndIncluding' in match:
                    endIncluding = match['versionEndIncluding']
                    if version_cmp(version, endIncluding) == 1:
                        continue;
                if 'versionStartExcluding' in match:
                    startExcluding = match['versionStartExcluding']
                    if version_cmp(version, startExcluding) != 1:
                        continue;
                if 'versionEndExcluding' in match:
                    endExcluding = match['versionEndExcluding']
                    if version_cmp(version, endExcluding) != 1:
                        continue;
                cve_info = {}
                cve_info['cve_id'] = cve_id
                cve_info['cvss'] = cvss
                cves.append(cve_info)
                found = True
                break

    return cves

# Get CVES that match CPE from the splunk
def get_cves(cves, part, vendor, product, version):
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

def get_cpe_variants(cpe):
    if cpe not in cpe_db:
        return None

    return cpe_db[cpe]

# Each product should contain the following:
# List of dictionaries that contains:
#   CPE ID 
#   list of all relevant CVEs
# build the product DB

class Product_file(csv.CSV_FILE):
    def implementation(self, tokens):
        global product_db
        product_db[tokens[0]] = {}

class Product_cpe_file(csv.CSV_FILE):
    def implementation(self, tokens):
        global product_db
        product_id = tokens[0]
        cpe_id = tokens[1]
        version = tokens[2]
        hw = tokens[3]
        if product_id not in product_db:
           print('ERROR: product :' + product_id)
           return
        product_entry = product_db[product_id]
        if cpe_id not in product_entry:
            product_entry[cpe_id] = {}
            cpe_entry = product_entry[cpe_id];
            cpe_entry['version'] = version
            cpe_entry['cves'] = []

class Cpe_file(csv.CSV_FILE):
    def implementation(self, tokens):
        global cpe_db
        cpe_id = tokens[0]
        if cpe_id not in cpe_db:
           cpe_db[cpe_id] = []
        cpe_entry = cpe_db[cpe_id]
        cpe_info = {}
        cpe_info['part'] = tokens[1]
        cpe_info['vendor']= tokens[2]
        cpe_info['product'] = tokens[3]
        cpe_entry.append(cpe_info)

product_db = {}
cpe_db = {}
def init_db():
    product_file = Product_file(CSV_HOME + PRODUCT_TABLE)
    product_file.process()

    product_cpe_file = Product_cpe_file(CSV_HOME + PRODUCT_CPE_TABLE)
    product_cpe_file.process()

    cpe_file = Cpe_file(CSV_HOME + CPE_TABLE)
    cpe_file.process()

def dump_db():
    print(product_db)
    print(cpe_db)
    for product_id,product_info in product_db.items():
        print('-----------------------')
        print('product id:' + product_id)
        for cpe_id, cpe_info in product_info.items():
            print(cpe_id)
            version = cpe_info['version']
            cves = cpe_info['cves']
            cpe_variants = get_cpe_variants(cpe_id)
            for variant in cpe_variants:
                print('++++')
                print(variant['part'])
                print(variant['vendor'])
                print(variant['product'])
                print(version)
                for cve in cves:
                    print(cve['cve_id'])

def get_incident(incidents_db, product_id, cve, cpe, version):
    for incident in incidents_db:
        if 'CVE' not in incident:
            continue
        if 'CPE' not in incident:
            continue
        if 'Version' not in incident:
            continue
        if 'Product_id' not in incident:
            continue
        if cve == incident['CVE'] and cpe == incident['CPE'] and version == incident['Version'] and product_id == incident['Product_id']:
            return incident

    return None

def insert_incident(incidents_file, incidents, product_id, cve, cpe, version, cvss):
    incident_values = []
    incident_values.append('99')
    incident_values.append(cve)
    incident_values.append(cpe)
    incident_values.append(version)
    incident_values.append(product_id)
    incident_values.append('9')
    incident_values.append('Open')
    incident_values.append('nvd')
    incident_values.append('time')
    incident_values.append('Creation time')
    incident_values.append('Jira ticket')
    incident_values.append('0')
    incident_values.append(cvss)

    incidents_file.insert_dic_line(incidents, incident_values)

    
init_db()

for product_id,product_info in product_db.items():
    for cpe_id, cpe_info in product_info.items():
        version = cpe_info['version']
        cves = cpe_info['cves']
        cpe_variants = get_cpe_variants(cpe_id)
        for variant in cpe_variants:
            get_cves(cves, variant['part'], variant['vendor'], variant['product'], version)

if debug:
    dump_db()

incident_file = csv.CSV_FILE(CSV_HOME + INCIDENT_TABLE)

#Load the content of incident table to a dictionary
#The matchin fileds in the incident table is product_id,cve,cpe,version
incidents = incident_file.to_dic();

if debug:
    print('=========================== indidents b4 !!!: ===================================================================')
    print(incidents)

for product_id,product_info in product_db.items():
    for cpe, cpe_info in product_info.items():
        if 'version' not in cpe_info:
            print('ERROR: no version in cpe: ' + cpe)
            continue
        if 'cves' not in cpe_info:
            #nothing to do for this cpe.
            continue
        version = cpe_info['version']
        if debug:
            print('>>>>> Processing ' + str(product_id) + ' ' + str(cpe) + ' ' + str(version))
        cves = cpe_info['cves']
        for cve in cves:
            cve_id = cve['cve_id']
            if debug:
                print('key: ' + product_id + ',' +  cve_id + ',' + cpe + ',' + version)
            res = get_incident(incidents, product_id, cve_id, cpe, version)
            if res is not None:
                continue
            insert_incident(incident_file, incidents, product_id, cve_id, cpe, version, cve['cvss'])

if debug:
    print('=========================== incidents after !!!: ===================================================================')
    print(incidents)

incident_file.from_dic(incidents)
