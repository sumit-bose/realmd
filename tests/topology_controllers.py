from __future__ import annotations

from pytest_mh import BackupTopologyController
from pytest_mh.conn import ProcessResult

from sssd_test_framework.config import SSSDMultihostConfig
from sssd_test_framework.hosts.ad import ADHost
from sssd_test_framework.hosts.client import ClientHost
from sssd_test_framework.hosts.samba import SambaHost
from sssd_test_framework.hosts.ipa import IPAHost
from sssd_test_framework.misc.ssh import retry_command

__all__ = [
    "ADTopologyController",
    "SambaTopologyController",
    "IPATopologyController",
]


class ProvisionedBackupTopologyController(BackupTopologyController[SSSDMultihostConfig]):
    """
    Provide basic restore functionality for topologies.
    """

    def __init__(self) -> None:
        super().__init__()

        self.provisioned: bool = False

    def init(self, *args, **kwargs):
        super().init(*args, **kwargs)
        self.provisioned = self.name in self.multihost.provisioned_topologies

    def topology_teardown(self) -> None:
        if self.provisioned:
            return

        super().topology_teardown()

    def teardown(self) -> None:
        if self.provisioned:
            self.restore_vanilla()
            return

        super().teardown()


class ClientTopologyController(ProvisionedBackupTopologyController):
    """
    Client Topology Controller.
    """

    pass


class ADTopologyController(ProvisionedBackupTopologyController):
    """
    AD Topology Controller.
    """

    @BackupTopologyController.restore_vanilla_on_error
    def topology_setup(self, client: ClientHost, provider: ADHost) -> None:
        if self.provisioned:
            self.logger.info(f"Topology '{self.name}' is already provisioned")
            return

        # Remove any existing Kerberos configuration and keytab
        client.fs.rm("/etc/krb5.conf")
        client.fs.rm("/etc/krb5.keytab")

        # Backup so we can restore to this state after each test
        super().topology_setup()


class IPATopologyController(ProvisionedBackupTopologyController):
    """
    IPA Topology Controller.
    """

    @BackupTopologyController.restore_vanilla_on_error
    def topology_setup(self, client: ClientHost, ipa: IPAHost) -> None:
        if self.provisioned:
            self.logger.info(f"Topology '{self.name}' is already provisioned")
            return

        #self.logger.info(f"Enrolling {client.hostname} into {ipa.domain}")
        self.logger.info(f"{client.hostname} into {ipa.domain}")
        self.logger.info("**************************"*77)

        # Remove any existing Kerberos configuration and keytab
        client.fs.rm("/etc/krb5.conf")
        client.fs.rm("/etc/krb5.keytab")

        # Backup ipa-client-install files
        client.fs.backup("/etc/ipa")
        client.fs.backup("/var/lib/ipa-client")

        # Join ipa domain
        #client.conn.exec(["realm", "leave", ipa.domain], input=ipa.adminpw)

        # Backup so we can restore to this state after each test
        super().topology_setup()


class SambaTopologyController(ADTopologyController):
    """
    Samba Topology Controller.
    """

    pass
