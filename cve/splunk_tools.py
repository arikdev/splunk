import splunklib.client as client
import splunklib.results as results
from time import sleep
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators

def connect_splunk(host, port, username, password):
    service = client.connect(
        host=host,
        port=port,
        username=username,
        password=password)

    return service


def search_splunk(service, search, max_fetched, func, *args):
    job = service.jobs.create(search, max_count=max_fetched)
    while True:
        while not job.is_ready():
            pass
        if job['isDone'] == '1':
            break
        sleep(0.05)

    kwargs_options = {"count" : max_fetched}
    reader = results.ResultsReader(job.results(**kwargs_options))

    for item in reader:
        if '_raw' in item:
            func(item['_raw'], *args)
