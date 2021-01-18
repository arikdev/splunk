import requests
import json

def get_cves(cpe_vendor, cpe_product):
    cves = []
    start_index = 0
    prev_results = 0
    count = 0
    while True:
        print('startIndex:' + str(start_index))
        r = requests.get(f'https://services.nvd.nist.gov/rest/json/cves/1.0?startIndex=%d&resultsPerPage=1024&cpeMatchString=cpe:2.3:*:%s:%s' % (start_index, cpe_vendor, cpe_product))
        j = json.loads(r.text)
        total_results = j['totalResults']
        print(total_results)
        if total_results == prev_results:
            break;
        prev_results = total_results
        result = j['result']
        items = result['CVE_Items']
        for item in items:
            count += 1
            print('-------------------------------------------- :'+ str(count))
            cve = item['cve']
            print(cve)
        start_index += total_results

    return list

#/home/manage/splunk/etc/apps/lookup_editor/lookups

cves = get_cves("google", "android")
print(cves)
