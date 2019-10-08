from netprobify.protocol.target import dscp_to_tos, Group


def test_dscp_to_tos():
    """Test of dscp_to_tos function."""
    assert dscp_to_tos(8) == 32
    assert dscp_to_tos(56) == 224


def test_group():
    """Test group creation."""
    grp = Group(
        name="group_example",
        src_ipv4="127.0.0.1",
        src_ipv6="::1",
        src_port_a=1000,
        src_port_z=1001,
        ip_payload_size=None,
        dscp=1,
        permit_target_auto_register=True,
    )

    assert grp.src_ipv4 == "127.0.0.1"
    assert grp.src_ipv6 == "::1"
    assert not grp.ip_payload_size

    grp = Group(
        name="group_example",
        src_ipv4=None,
        src_ipv6="::1",
        src_port_a=1000,
        src_port_z=1001,
        ip_payload_size=None,
        dscp=1,
        permit_target_auto_register=True,
    )

    assert not grp.src_ipv4
    assert grp.src_ipv6 == "::1"
    assert not grp.ip_payload_size

    grp = Group(
        name="group_example",
        src_ipv4="999.999.9999.9999",
        src_ipv6=None,
        src_port_a=1000,
        src_port_z=1001,
        ip_payload_size=None,
        dscp=1,
        permit_target_auto_register=True,
    )

    assert not grp.src_ipv4
    assert not grp.src_ipv6
    assert not grp.ip_payload_size

    grp = Group(
        name="group_example",
        src_ipv4="999.999.9999.9999",
        src_ipv6="I:AM:NOT:AN:IPV6:ADDRESS",
        src_port_a=1000,
        src_port_z=1001,
        ip_payload_size=1024,
        dscp=1,
        permit_target_auto_register=True,
    )

    assert not grp.src_ipv4
    assert not grp.src_ipv6
    assert grp.ip_payload_size == 1024

    grp = Group(
        name="group_example",
        src_ipv4="127.0.0.2",
        src_ipv6="I:AM:STILL:NOT:AN:IPV6:ADDRESS",
        src_port_a=1000,
        src_port_z=1001,
        ip_payload_size=0,
        dscp=1,
        permit_target_auto_register=True,
    )

    assert grp.src_ipv4 == "127.0.0.2"
    assert not grp.src_ipv6
    assert grp.ip_payload_size == 0
