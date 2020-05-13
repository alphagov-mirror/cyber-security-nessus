from unittest.mock import call
import process_scans

import vcr


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
    process_scans.process_csv(csv)

    expected = [call('1,1,1,"1\n1"\n2,2,2,"2\n2"\n')]

    assert process_scans.process_csv.call_args_list == expected


# @vcr.use_cassette
# def test_find_scans(capsys):
#     process_scans.find_scans()
#     captured = capsys.readouterr()
#     assert captured.out == "Scan localhost has not run.\n"


# @vcr.use_cassette
# def test_create_log_stream():
#     group_name = "/aws/lambda/nessus_scanner"
#     stream_name = "2020/05/03/[$LATEST]09788309846457e5b9dfc1d5dfae648e"
#     result = process_scans.create_log_stream(group_name, stream_name)
#     expected = "49689435985798542297993617458544907186660420414545737314"
#     assert result == expected
