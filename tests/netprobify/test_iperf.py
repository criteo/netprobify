from unittest import mock

import pytest
from netprobify.protocol.iperf import Iperf


@pytest.fixture(name="test_target")
def create_target():
    """Create fixture for test target."""
    return Iperf(
        "localhost",
        active=True,
        description="localhost",
        destination="127.0.0.1",
        config_destination="127.0.0.1",
        address_family="ipv4",
        dst_port=0,
        threshold=1,
        state="in production",
        alert_level="paging",
        is_dynamic=False,
        dns_update_interval=0,
        groups={"test"},
        duration=5,
        bandwidth="1M",
        protocol="udp",
        num_streams="2",
        lifetime={"days": "1"},
        creation_date=None,
    )


@mock.patch("netprobify.protocol.iperf.subprocess.check_output")
def test_send_packets(mock_check_output, test_target):
    """Check iperf result is parsed properly."""
    mock_check_output.return_value = """
20190322165127,127.0.0.1,5001,127.0.0.1,49583,3,0.0-5.0,657090,1051051,0.005,0,446,0.000,1
20190322165127,127.0.0.1,5001,127.0.0.1,60162,4,0.0-5.0,654150,1046345,0.003,1,446,0.224,0
"""

    result = []
    test_target.send_packets(result, "DEBUG")

    assert result == [
        {
            "alert_level": "paging",
            "bandwidth": 2097396,
            "destination": "127.0.0.1",
            "address_family": "ipv4",
            "duration": 5,
            "groups": {"test"},
            "loss": 1,
            "name": "localhost",
            "out_of_order": 1,
            "probing_type": "iperf",
            "sent": 892,
            "state": "in production",
        }
    ]


@mock.patch("netprobify.protocol.iperf.subprocess.check_output")
def test_send_packets_invalid_result(mock_check_output, test_target):
    """Check the module does not fail when output is invalid."""
    # invalid output
    mock_check_output.return_value = "1"
    result = []
    test_target.send_packets(result, "DEBUG")
