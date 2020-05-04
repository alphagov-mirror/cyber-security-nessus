import os
import sys

import pytest
import vcr

currentdir = os.path.dirname(__file__)
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)

import nessus as n
import schedule_scans as s





@vcr.use_cassette()
def test_advanced_dynamic_policy_template_uuid():
    """Should return the `uuid` of the template with the name `Advanced Dynamic Scan`"""
    result = s.advanced_dynamic_policy_template_uuid()
    expected = "939a2145-95e3-0c3f-f1cc-761db860e4eed37b6eee77f9e101"
    assert result == expected
