"""SSSD predefined well-known topologies."""

from __future__ import annotations

from enum import unique
from typing import final

from pytest_mh import KnownTopologyBase, KnownTopologyGroupBase, Topology, TopologyDomain

from sssd_test_framework.config import SSSDTopologyMark
from .topology_controllers import (
    ADTopologyController,
    IPATopologyController,
    SambaTopologyController,
)

__all__ = [
    "KnownTopology",
    "KnownTopologyGroup",
]


@final
@unique
class KnownTopology(KnownTopologyBase):
    """
    Well-known topologies that can be given to ``pytest.mark.topology``
    directly. It is expected to use these values in favor of providing
    custom marker values.

    .. code-block:: python
        :caption: Example usage

        @pytest.mark.topology(KnownTopology.LDAP)
        def test_ldap(client: Client, ldap: LDAP):
            assert True
    """

    """
    Client = SSSDTopologyMark(
        name="client",
        topology=Topology(TopologyDomain("sssd", client=1)),
        controller=ClientTopologyController(),
        fixtures=dict(client="sssd.client[0]"),
    )
    """
    """
    .. topology-mark:: KnownTopology.Client
    """

    AD = SSSDTopologyMark(
        name="ad",
        topology=Topology(TopologyDomain("sssd", client=1, ad=1)),
        controller=ADTopologyController(),
        domains=dict(test="sssd.ad[0]"),
        fixtures=dict(client="sssd.client[0]", ad="sssd.ad[0]", provider="sssd.ad[0]"),
    )
    """
    .. topology-mark:: KnownTopology.AD
    """

    Samba = SSSDTopologyMark(
        name="samba",
        topology=Topology(TopologyDomain("sssd", client=1, samba=1)),
        controller=SambaTopologyController(),
        domains={"test": "sssd.samba[0]"},
        fixtures=dict(client="sssd.client[0]", samba="sssd.samba[0]", provider="sssd.samba[0]"),
    )
    """
    .. topology-mark:: KnownTopology.Samba
    """

    IPA = SSSDTopologyMark(
        name="ipa",
        topology=Topology(TopologyDomain("sssd", client=1, ipa=1)),
        controller=IPATopologyController(),
        domains=dict(test="sssd.ipa[0]"),
        fixtures=dict(client="sssd.client[0]", ipa="sssd.ipa[0]", provider="sssd.ipa[0]"),
    )
    """
    .. topology-mark:: KnownTopology.IPA
    """


class KnownTopologyGroup(KnownTopologyGroupBase):
    """
    Groups of well-known topologies that can be given to ``pytest.mark.topology``
    directly. It is expected to use these values in favor of providing
    custom marker values.

    The test is parametrized and runs multiple times, once per each topology.

    .. code-block:: python
        :caption: Example usage (runs on AD, IPA, LDAP and Samba topology)

        @pytest.mark.topology(KnownTopologyGroup.AnyProvider)
        def test_ldap(client: Client, provider: GenericProvider):
            assert True
    """

    AnyAD = [KnownTopology.AD, KnownTopology.Samba]
    """
    .. topology-mark:: KnownTopologyGroup.AnyAD
    """

    AnyProvider = [KnownTopology.AD, KnownTopology.Samba]
    """
    .. topology-mark:: KnownTopologyGroup.AnyProvider
    """
