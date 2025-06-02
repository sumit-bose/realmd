from __future__ import annotations

import pytest
import time
import os
import sys


from .topology import KnownTopology, KnownTopologyGroup
from sssd_test_framework.roles.ad import AD
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.roles.generic import GenericADProvider
from sssd_test_framework.utils.realmd import RealmUtils


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_realm_discover(client: Client, provider: Any):
    """
    :title: realm discover a domain
    :steps:
        1. Request information about a domain
    :expectedresults:
        1. Information about a domain is retrieved
    """
    r = client.realm.discover(provider.host.domain, args=["--all", "--verbose"])
    assert provider.host.domain in r.stdout, "realm failed to discover domain info"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_realm_join(client: Client, provider: Any):
    """
    :title: realm join
    :steps:
        1. Join a client system to the domain
    :expectedresults:
        1. A client system joined to the domain successfully
    """
    r = client.realm.join(provider.host.domain, krb=False, user=provider.host.adminuser, password=provider.host.adminpw)
    assert r.rc == 0, "realm join operation failed!"
    assert "Successfully enrolled machine in realm" in r.stderr, "realm failed to join client to the domain"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_realm_leave(client: Client, provider: Any):
    """
    :title: realm leave
    :steps:
    :expectedresults:
    """
    client.realm.join(provider.host.domain, krb=False, user=provider.host.adminuser, password=provider.host.adminpw)
    r = client.realm.leave(provider.host.domain)
    assert r.rc == 0, "realm leave operation failed!"
    assert "Successfully unenrolled machine from realm" in r.stderr, "realm failed to leave domain!"


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopologyGroup.AnyAD)
def test_realm_list(client: Client, provider: Any):
    """
    :title: realm list
    :steps:
    :expectedresults:
    """
    r = client.realm.list(args=["--all"])
    assert r.rc == 0, "realm list operation failed!"
    assert provider.host.domain in r.stdout, "realm failed to list domain"
