"""Network exposure tests (static)."""

from __future__ import annotations

from .hcl import load

CFG = load()


def test_database_not_publicly_accessible():
    dbs = CFG.resources("aws_db_instance")
    assert dbs, "no database defined"
    for db in dbs:
        assert db.body.get("publicly_accessible") is False, f"{db.address} must set publicly_accessible = false"


def test_no_public_ips_on_private_resources():
    for lt in CFG.resources("aws_launch_template"):
        for ni in lt.body.get("network_interfaces", []):
            assert ni.get("associate_public_ip_address") is False, f"{lt.address} assigns a public IP"
    for inst in CFG.resources("aws_instance"):
        assert inst.body.get("associate_public_ip_address") is False, f"{inst.address} assigns a public IP"
    for subnet in CFG.resources("aws_subnet"):
        assert subnet.body.get("map_public_ip_on_launch") is False, f"{subnet.address} auto-assigns public IPs"
    assert not CFG.resources("aws_eip"), "Elastic IPs are not expected anywhere in this design"


def test_no_nat_or_internet_route_for_private_tiers():
    assert not CFG.resources("aws_nat_gateway"), "private tiers must not have a NAT path to the internet"
    for route in CFG.resources("aws_route"):
        if "gateway_id" in route.body:
            assert route.body["route_table_id"] == "${aws_route_table.public.id}", (
                f"{route.address}: internet gateway route outside the public route table"
            )
    for rt in CFG.resources("aws_route_table"):
        assert "route" not in rt.body, f"{rt.address}: inline routes are not allowed (use aws_route)"


def test_only_alb_accepts_traffic_from_cidrs():
    """Every ingress rule except the ALB's HTTPS rule references a security group."""
    for rule in CFG.resources("aws_vpc_security_group_ingress_rule"):
        if rule.name == "alb_https":
            assert rule.body["from_port"] == 443 and rule.body["to_port"] == 443
            assert rule.body["cidr_ipv4"] == "${each.value}"  # var.alb_ingress_cidrs
            continue
        assert "referenced_security_group_id" in rule.body, f"{rule.address} must reference a security group"
        assert "cidr_ipv4" not in rule.body and "cidr_ipv6" not in rule.body, f"{rule.address} opens a CIDR"


def test_no_open_egress():
    for rule in CFG.resources("aws_vpc_security_group_egress_rule"):
        assert rule.body.get("ip_protocol") != "-1", f"{rule.address}: all-protocol egress"
        assert rule.body.get("cidr_ipv4") not in ("0.0.0.0/0",), f"{rule.address}: egress to the internet"


def test_no_inline_security_group_rules():
    """Inline ingress/egress blocks hide rules from review; standalone rules only."""
    for sg in CFG.resources("aws_security_group"):
        assert "ingress" not in sg.body and "egress" not in sg.body, f"{sg.address} uses inline rules"


def test_database_and_endpoints_have_no_egress_rules():
    egress_targets = [r.body["security_group_id"] for r in CFG.resources("aws_vpc_security_group_egress_rule")]
    assert "${aws_security_group.db.id}" not in egress_targets, "database security group must not allow egress"
    assert "${aws_security_group.endpoints.id}" not in egress_targets, "endpoint security group must not allow egress"


def test_expected_tier_flows():
    rules = {r.name: r.body for r in CFG.resources("aws_vpc_security_group_ingress_rule")}
    assert rules["app_from_alb"]["referenced_security_group_id"] == "${aws_security_group.alb.id}"
    assert rules["app_from_alb"]["from_port"] == "${var.app_port}"
    assert rules["db_from_app"]["referenced_security_group_id"] == "${aws_security_group.app.id}"
    assert rules["db_from_app"]["from_port"] == "${var.db_port}" == rules["db_from_app"]["to_port"]


def test_nacls_never_allow_all_traffic():
    for rule in CFG.resources("aws_network_acl_rule"):
        if rule.body.get("rule_action") == "allow":
            assert rule.body.get("protocol") == "tcp", f"{rule.address}: allow rule must be protocol-specific"
            assert "from_port" in rule.body and "to_port" in rule.body


def test_db_nacl_only_admits_app_subnets():
    db_rules = [r for r in CFG.resources("aws_network_acl_rule") if r.body.get("network_acl_id") == "${aws_network_acl.db.id}"]
    assert db_rules
    for rule in db_rules:
        assert "app_cidrs" in rule.body["cidr_block"], f"{rule.address}: DB NACL rule not limited to app subnets"


def test_default_security_group_is_locked():
    sgs = CFG.resources("aws_default_security_group")
    assert sgs and all("ingress" not in s.body and "egress" not in s.body for s in sgs)


def test_alb_is_https_only():
    listeners = CFG.resources("aws_lb_listener")
    assert len(listeners) == 1, "exactly one listener (HTTPS) expected; no plaintext HTTP listener"
    lst = listeners[0].body
    assert lst["protocol"] == "HTTPS" and lst["port"] == 443
    assert lst["ssl_policy"].startswith("ELBSecurityPolicy-TLS13-1-2")


def test_imdsv2_required():
    for lt in CFG.resources("aws_launch_template"):
        md = lt.body["metadata_options"][0]
        assert md["http_tokens"] == "required" and md["http_put_response_hop_limit"] == 1
