"""Scope enforcement — the guard that must not be bypassable by accident."""

from __future__ import annotations

import json

import pytest

from netintel.core.scope import ScopePolicy
from netintel.core.targets import parse_targets
from netintel.errors import ScopeViolationError, TargetError


def test_private_ranges_are_permitted_by_default():
    policy = ScopePolicy.private_only()
    policy.check(parse_targets("192.168.1.0/29"))
    policy.check(parse_targets("10.0.0.1"))
    policy.check(parse_targets("172.16.0.1"))


def test_public_targets_are_refused_by_default():
    policy = ScopePolicy.private_only()
    with pytest.raises(ScopeViolationError, match="outside the authorised scope"):
        policy.check(parse_targets("8.8.8.8"))


def test_a_single_public_address_taints_a_mixed_range():
    policy = ScopePolicy.private_only()
    with pytest.raises(ScopeViolationError):
        policy.check(parse_targets("192.168.1.1, 1.1.1.1"))


def test_explicit_authorisation_permits_a_public_prefix():
    policy = ScopePolicy.from_prefixes(["203.0.113.0/24"])
    policy.check(parse_targets("203.0.113.10"))
    assert policy.allow_public is True


def test_authorisation_is_not_a_blanket_grant():
    policy = ScopePolicy.from_prefixes(["203.0.113.0/24"])
    with pytest.raises(ScopeViolationError):
        policy.check(parse_targets("198.51.100.1"))


def test_private_space_stays_allowed_alongside_an_explicit_scope():
    policy = ScopePolicy.from_prefixes(["203.0.113.0/24"])
    policy.check(parse_targets("192.168.0.1"))


def test_host_count_limit_is_enforced():
    policy = ScopePolicy(max_hosts=4)
    with pytest.raises(ScopeViolationError, match="exceeds the configured limit"):
        policy.check(parse_targets("192.168.1.0/24"))


def test_violation_message_names_the_offending_addresses():
    policy = ScopePolicy.private_only()
    with pytest.raises(ScopeViolationError) as excinfo:
        policy.check(parse_targets("1.1.1.1"))
    assert "1.1.1.1" in str(excinfo.value)
    assert "--authorized-scope" in str(excinfo.value)


def test_scope_file_is_loaded(tmp_path):
    path = tmp_path / "scope.json"
    path.write_text(
        json.dumps(
            {
                "authorized_prefixes": ["198.51.100.0/24"],
                "max_hosts": 32,
                "note": "engagement ACME-2024-11",
            }
        )
    )
    policy = ScopePolicy.load(path)
    policy.check(parse_targets("198.51.100.7"))
    assert policy.max_hosts == 32
    assert "ACME" in policy.note


def test_missing_scope_file_falls_back_to_private_only(tmp_path):
    policy = ScopePolicy.load(tmp_path / "absent.json")
    assert policy.allow_public is False


def test_malformed_scope_file_is_an_error_not_a_silent_default(tmp_path):
    path = tmp_path / "scope.json"
    path.write_text("{not json")
    with pytest.raises(TargetError):
        ScopePolicy.load(path)


def test_scope_file_with_a_bad_prefix_is_rejected(tmp_path):
    path = tmp_path / "scope.json"
    path.write_text(json.dumps({"authorized_prefixes": ["not-a-network"]}))
    with pytest.raises(TargetError):
        ScopePolicy.load(path)


def test_environment_variable_selects_the_scope_file(tmp_path, monkeypatch):
    path = tmp_path / "env-scope.json"
    path.write_text(json.dumps({"authorized_prefixes": ["203.0.113.0/24"]}))
    monkeypatch.setenv("NETINTEL_SCOPE_FILE", str(path))
    ScopePolicy.load().check(parse_targets("203.0.113.1"))
