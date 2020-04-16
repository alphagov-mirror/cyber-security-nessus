import nessus as n
from unittest.mock import call

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
