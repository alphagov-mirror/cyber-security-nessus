from unittest.mock import call
import process_scans as ps


def test_process_csv(mocker):
    """The process csv function should forward each csv row
    separately. Rows may contain newline(\n) characters and there
    should be handled appropriately.

    """

    csv = """1,1,1,"1
1"
2,2,2,"2
2"
"""
    mocker.patch("process_scans.process_csv")
    ps.process_csv(csv)

    expected = [call('1,1,1,"1\n1"\n2,2,2,"2\n2"\n')]

    assert ps.process_csv.call_args_list == expected
