import os,sys,inspect
currentdir = os.path.dirname(__file__)
parentdir = os.path.dirname(currentdir)
sys.path.insert(0,parentdir)
import vcr
import requests
import nessus as n
from unittest.mock import call
import logging
logging.basicConfig() # you need to initialize logging, otherwise you will not see anything from vcrpy
vcr_log = logging.getLogger("vcr")
vcr_log.setLevel(logging.INFO)

my_vcr = vcr.VCR(
    record_mode='once',
    match_on=['uri', 'method'],
)


def test_process_csv(mocker):
    """The process csv function should forward each csv row
    separately. Rows may contain newline(\n) characters and there
    should be handled appropriately.

    """

    csv = '''1,1,1,"1
1"
2,2,2,"2
2"
'''
    mocker.patch("nessus.send_to_cloudwatch")
    n.process_csv(csv)

    expected = [call(['1', '1', '1', '1\n1']), call(['2', '2', '2', '2\n2'])]

    assert n.send_to_cloudwatch.call_args_list == expected


@my_vcr.use_cassette("tests/fixtures/cassettes/test_requests.yaml")
def aatest_requests():
    r = requests.get("https://www.google.co.uk/")
    print(r)
    print(r.text)

@vcr.use_cassette("tests/fixtures/cassettes/test_get_param_from_ssm.yaml")
def test_get_param_from_ssm():
    param = n.get_param_from_ssm("access_key")
    assert param == "fakeparam"
