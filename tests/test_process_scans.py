from unittest.mock import call
import process_scans as ps

import vcr


my_vcr = vcr.VCR(
    record_mode="none",
    match_on=["uri", "method", "body"],
    cassette_library_dir="tests/fixtures/cassettes",
    path_transformer=vcr.VCR.ensure_suffix(".yaml"),
)


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


@my_vcr.use_cassette()
def test_find_scans(capsys):
    ps.find_scans()
    captured = capsys.readouterr()
    assert captured.out == "Scan localhost has not run.\n"


@my_vcr.use_cassette(record_mode="once")
def test_create_log_stream():
    group_name = "/aws/lambda/nessus_scanner"
    stream_name = "2020/05/03/[$LATEST]09788309846457e5b9dfc1d5dfae648e"
    result = ps.create_log_stream(group_name, stream_name)
    expected = "49689435985798542297993617458544907186660420414545737314"
    assert result == expected
