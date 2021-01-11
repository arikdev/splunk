from __future__ import print_function
from io import BytesIO
from zipfile import ZipFile
import requests
import json

years = [
    "2021",
    "2020",
    "2019",
    "2018",
    "2017",
    "2016",
    "2015",
    "2014",
    "2013",
    "2012",
    "2011",
    "2010",
    "2009",
    "2008",
    "2007"
]

def cpe_exists(item):
      if 'configurations' not in item:
          return False;
      conf = item['configurations']
      if 'nodes' not in conf:
          return False
      nodes = conf['nodes']
      for node in nodes:
          if 'cpe_match' in node:
              return True
      return False

num_of_found_cpe = 0
num_of_not_found_cpe = 0

for year in years:
    url = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%s.json.zip' % year
    response = requests.get(url)
    data = {}
    zipfile = ZipFile(BytesIO(response.content)) 

    for i in zipfile.namelist():
        if i == "nvdcve-1.1-%s.json" % year:
            data = json.loads(zipfile.read(i))
            break

    for d in data["CVE_Items"]:
        if cpe_exists(d) == False:
           num_of_not_found_cpe += 1
           continue
        num_of_found_cpe += 1
        print(json.dumps(d))

f = open("cve_lookout_log.txt", "w")
f.write("Summery: Foud CPE: " + str(num_of_found_cpe) + " Not found:" + str(num_of_not_found_cpe) + "\n")
f.close()
