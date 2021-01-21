from datetime import datetime
import requests
import json

CVS_HOME = '/home/manage/splunk/etc/apps/lookup_editor/lookups/'
CPE_TABLE = 'vul_cpe.csv'
PRODUCT_CPE_TABLE = 'vul_product_cpe.csv'

cves = []

def get_cves(cpe_part, cpe_vendor, cpe_product, cpe_version):
    start_index = 0
    prev_results = 0
    while True:
        r = requests.get(f'https://services.nvd.nist.gov/rest/json/cves/1.0?startIndex=%d&resultsPerPage=1024&cpeMatchString=cpe:2.3:%s:%s:%s:%s' % (start_index, cpe_part, cpe_vendor, cpe_product, cpe_version))
        j = json.loads(r.text)
        total_results = j['totalResults']
        if total_results == prev_results:
            break;
        prev_results = total_results
        result = j['result']
        items = result['CVE_Items']
        for item in items:
            cve = item['cve']
            meta_data = cve['CVE_data_meta']
            id = meta_data['ID']
            if id in cves:
                continue
            cves.append(id)
            print(item)
        start_index += total_results

def get_cpe_fields(cpe_id):
    first = True
    with open(CVS_HOME + CPE_TABLE, 'r') as fp:
        for line in fp:
            if first: #If the header of the csv 
                first = False
                continue 
            line = line[:-1]
            tokens = line.split(',')
            line_cpe_id = tokens[0]
            if  line_cpe_id == cpe_id:
                return tokens[1],tokens[2],tokens[3]

    return 'None','None', 'None'

f = open("cve_log.txt", "w")
now = datetime.now()
current_time = now.strftime("%H:%M:%S")
f.write('------------------Started---------------:' + current_time + '\n')
first = True
with open(CVS_HOME + PRODUCT_CPE_TABLE, 'r') as fp:
    for line in fp:
        if first: #If the header of the csv 
            first = False
            continue 
        line = line[:-1]
        tokens = line.split(',')
        product_id = tokens[0]
        cpe_id = tokens[1]
        version = tokens[2]
        f.write("--- Procssgin: " + product_id + ' ' + cpe_id + ' ' + version + '\n')
        part,vendor,product = get_cpe_fields(cpe_id)
        if part == 'None':
            f.write('ERROR: faild processing:'+ product_id + ' cpe:' + cpe_id + '\n')
            continue
        get_cves(part, vendor, product, version)

now = datetime.now()
current_time = now.strftime("%H:%M:%S")
f.write('------------------Finished---------------:' + current_time + '\n')
f.write(str(len(cves)) + '\n')

