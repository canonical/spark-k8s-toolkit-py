"""Abstract class definition for service that manages service accounts registry."""

from abc import ABC, abstractmethod

from spark8t.domain import (
    PropertyFile,
    ServiceAccount,
)
from spark8t.utils import WithLogging


class AbstractServiceAccountRegistry(WithLogging, ABC):
    """Abstract class for implementing service that manages spark ServiceAccount resources."""

    @abstractmethod
    def all(self, namespace: str | None = None) -> list[ServiceAccount]:
        """Return all existing service accounts."""
        pass

    @abstractmethod
    def create(self, service_account: ServiceAccount) -> str:
        """Create a new service account and return ids associated id.

        Args:
            service_account: ServiceAccount to be stored in the registry

        Return:
            The YAML manifest of the resources that are to be created.
        """
        pass

    @abstractmethod
    def set_configurations(self, account_id: str, configurations: PropertyFile) -> str:
        """Set a new service account configuration for the provided service account id.

        Args:
            account_id: account id for which configuration ought to be set
            configurations: PropertyFile representing the new configuration to be stored
        """
        pass

    @abstractmethod
    def delete(self, account_id: str) -> str:
        """Delete the service account associated with the provided id.

        Args:
            account_id: service account id to be deleted
        """
        pass

    @abstractmethod
    def set_primary(self, account_id: str, namespace: str | None) -> str | None:
        """Set the primary account to the one related to the provided account id.

        Args:
            account_id: account id to be elected as new primary account
        """
        pass

    def get_primary(self, namespace: str | None = None) -> ServiceAccount | None:
        """Return the primary service account. None is there is no primary service account."""
        all_accounts = self.all(namespace)

        if len(all_accounts) == 0:
            self.logger.warning("There are no service account available.")
            return None

        primary_accounts = [
            account for account in all_accounts if account.primary is True
        ]
        if len(primary_accounts) == 0:
            self.logger.warning("There are no primary service account available.")
            return None

        if len(primary_accounts) > 1:
            self.logger.warning(
                f"More than one account was found: {','.join([account.name for account in primary_accounts])}. "
                f"Choosing the first: {primary_accounts[0].name}. "
                "Note that this may lead to un-expected behaviour if the other primary is chosen"
            )

        return primary_accounts[0]

    @abstractmethod
    def get(self, account_id: str) -> ServiceAccount | None:
        """Return the service account associated with the provided account id. None if no account was found.

        Args:
            account_id: account id to be used for retrieving the service account.
        """
        pass
