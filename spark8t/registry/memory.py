"""K8s services module."""

from __future__ import annotations

from spark8t.domain import (
    PropertyFile,
    ServiceAccount,
)
from spark8t.exceptions import (
    AccountNotFound,
)
from spark8t.registry.base import AbstractServiceAccountRegistry


class InMemoryAccountRegistry(AbstractServiceAccountRegistry):
    """In memory implementation for account registry."""

    def __init__(self, cache: dict[str, ServiceAccount]):
        self.cache = cache

        self._consistency_check()

    def _consistency_check(self):
        primaries = [account for account in self.all() if account.primary is True]

        if len(primaries) > 1:
            self.logger.warning(
                "There exists more than one primary in the service account registry."
            )

    def all(self, namespace: str | None = None) -> list[ServiceAccount]:
        """Return all existing service accounts."""
        return [
            service_account
            for service_account in self.cache.values()
            if namespace is None or namespace == service_account.namespace
        ]

    def create(self, service_account: ServiceAccount) -> str:
        """Create a new service account and return ids associated id.

        Args:
            service_account: ServiceAccount to be stored in the registry
        """
        if (service_account.primary is True) and any(
            account.primary for account in self.all()
        ):
            self.logger.info(
                "Primary service account provided. Switching primary account from account"
            )
            for _account_id, account in self.cache.items():
                if account.primary is True:
                    self.logger.debug(
                        f"Setting primary of account {account.id} to False"
                    )
                    account.primary = False

        self.cache[service_account.id] = service_account
        return service_account.id

    def delete(self, account_id: str) -> str:
        """Delete the service account associated with the provided id.

        Args:
            account_id: service account id to be deleted
        """
        return self.cache.pop(account_id).id

    def set_primary(self, account_id: str, namespace: str | None = None) -> str:
        """Set the primary account to the one related to the provided account id.

        Args:
            account_id: account id to be elected as new primary account
        """
        if account_id not in self.cache.keys():
            raise AccountNotFound(account_id)

        if any(account.primary for account in self.all()):
            self.logger.info("Switching primary account")
            for account in self.cache.values():
                if account.primary is True:
                    self.logger.debug(
                        f"Setting primary of account {account.id} to False"
                    )
                    account.primary = False

        self.cache[account_id].primary = True
        return account_id

    def set_configurations(self, account_id: str, configurations: PropertyFile) -> str:
        """Set a new service account configuration for the provided service account id.

        Args:
            account_id: account id for which configuration ought to be set
            configurations: PropertyFile representing the new configuration to be stored
        """
        if account_id not in self.cache.keys():
            raise AccountNotFound(account_id)

        self.cache[account_id].extra_confs = configurations
        return account_id

    def get(self, account_id: str) -> ServiceAccount | None:
        """Get service account."""
        return self.cache.get(account_id)
