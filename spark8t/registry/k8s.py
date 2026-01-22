"""Kubernetes service account registry."""

from __future__ import annotations

from typing import Any

from spark8t.domain import (
    KubernetesResourceType,
    PropertyFile,
    ServiceAccount,
)
from spark8t.exceptions import (
    AccountNotFound,
    K8sResourceNotFound,
    ResourceAlreadyExists,
)
from spark8t.kube_interface.base import AbstractKubeInterface
from spark8t.literals import (
    HUB_LABEL,
    MANAGED_BY_LABELNAME,
    PRIMARY_LABELNAME,
    SPARK8S_LABEL,
)
from spark8t.registry.base import AbstractServiceAccountRegistry
from spark8t.utils import PercentEncodingSerializer


class K8sServiceAccountRegistry(AbstractServiceAccountRegistry):
    """Class implementing a ServiceAccountRegistry, based on K8s."""

    _kubernetes_key_serializer = PercentEncodingSerializer("_")

    def __init__(self, kube_interface: AbstractKubeInterface):
        self.kube_interface = kube_interface

    def all(self, namespace: str | None = None) -> list[ServiceAccount]:
        """Return all existing service accounts."""
        service_accounts = self.kube_interface.get_service_accounts(
            namespace=namespace, labels=[f"{MANAGED_BY_LABELNAME}={SPARK8S_LABEL}"]
        )
        return [
            self._build_service_account_from_raw(raw["metadata"])
            for raw in service_accounts
        ]

    @staticmethod
    def _get_secret_name(name):
        return f"{SPARK8S_LABEL}-sa-conf-{name}"

    @staticmethod
    def _get_integration_hub_secret_name(name):
        return f"{HUB_LABEL}-{name}"

    def _retrieve_secret_configurations(
        self, name: str, namespace: str, secret_name: str
    ) -> PropertyFile:
        try:
            secret = self.kube_interface.get_secret(secret_name, namespace=namespace)[
                "data"
            ]
        except Exception:
            return PropertyFile.empty()

        return PropertyFile(
            {
                self._kubernetes_key_serializer.deserialize(key): value
                for key, value in secret.items()
            }
        )

    def _build_service_account_from_raw(self, metadata: dict[str, Any]):
        name = metadata["name"]
        namespace = metadata["namespace"]
        primary = PRIMARY_LABELNAME in metadata.get("labels", {})

        account_secret_name = self._get_secret_name(name)
        integration_hub_secret_name = self._get_integration_hub_secret_name(name)

        return ServiceAccount(
            name=name,
            namespace=namespace,
            primary=primary,
            api_server=self.kube_interface.api_server,
            extra_confs=self._retrieve_secret_configurations(
                name, namespace, account_secret_name
            ),
            integration_hub_confs=self._retrieve_secret_configurations(
                name, namespace, integration_hub_secret_name
            ),
        )

    def set_primary(self, account_id: str, namespace: str | None = None) -> str | None:
        """Set the primary account to the one related to the provided account id.

        Args:
            account_id: account id to be elected as new primary account
        """
        # Relabeling primary
        primary_account = self.get_primary(namespace)

        if primary_account is not None:
            self.kube_interface.remove_label(
                resource_type=KubernetesResourceType.SERVICEACCOUNT,
                resource_name=primary_account.name,
                label=f"{PRIMARY_LABELNAME}",
                namespace=primary_account.namespace,
            )
            self.kube_interface.remove_label(
                resource_type=KubernetesResourceType.ROLEBINDING,
                resource_name=f"{primary_account.name}-role-binding",
                label=f"{PRIMARY_LABELNAME}",
                namespace=primary_account.namespace,
            )

        service_account = self.get(account_id)

        if service_account is None:
            raise AccountNotFound(account_id)

        self.kube_interface.set_label(
            resource_type=KubernetesResourceType.SERVICEACCOUNT,
            resource_name=service_account.name,
            label=f"{PRIMARY_LABELNAME}=True",
            namespace=service_account.namespace,
        )
        self.kube_interface.set_label(
            resource_type=KubernetesResourceType.ROLEBINDING,
            resource_name=f"{service_account.name}-role-binding",
            label=f"{PRIMARY_LABELNAME}=True",
            namespace=service_account.namespace,
        )

        return account_id

    def create(self, service_account: ServiceAccount, dry_run=False) -> str:
        """Create a new service account and return ids associated id.

        Args:
            service_account: ServiceAccount to be stored in the registry
        """
        username = service_account.name
        namespace = service_account.namespace
        account_id = service_account.id
        configurations = service_account.extra_confs

        rolename = username + "-role"
        rolebindingname = username + "-role-binding"
        secretname = self._get_secret_name(username)

        # Check if the resources to be created already exist in K8s cluster
        if not dry_run and self.kube_interface.exists(
            resource_type=KubernetesResourceType.SERVICEACCOUNT,
            resource_name=username,
            namespace=namespace,
        ):
            raise ResourceAlreadyExists(
                "Could not create the service account. "
                f"A {KubernetesResourceType.SERVICEACCOUNT} with name '{username}' already exists."
            )

        if not dry_run and self.kube_interface.exists(
            resource_type=KubernetesResourceType.ROLE,
            resource_name=rolename,
            namespace=namespace,
        ):
            raise ResourceAlreadyExists(
                "Could not create the service account. "
                f"A {KubernetesResourceType.ROLE} with name '{rolename}' already exists."
            )

        if not dry_run and self.kube_interface.exists(
            resource_type=KubernetesResourceType.ROLEBINDING,
            resource_name=rolebindingname,
            namespace=namespace,
        ):
            raise ResourceAlreadyExists(
                "Could not create the service account. "
                f"A {KubernetesResourceType.ROLEBINDING} with name '{rolebindingname}' already exists."
            )

        sa_manifest = self.kube_interface.create(
            resource_type=KubernetesResourceType.SERVICEACCOUNT,
            resource_name=username,
            namespace=namespace,
            dry_run=dry_run,
            **{"username": username},
        )
        role_manifest = self.kube_interface.create(
            resource_type=KubernetesResourceType.ROLE,
            resource_name=rolename,
            namespace=namespace,
            dry_run=dry_run,
            **{"username": username},
        )
        role_binding_manifest = self.kube_interface.create(
            resource_type=KubernetesResourceType.ROLEBINDING,
            resource_name=rolebindingname,
            namespace=namespace,
            role=rolename,
            dry_run=dry_run,
            serviceaccount=account_id,
            username=username,
        )
        secret_manifest = self.kube_interface.create(
            resource_type=KubernetesResourceType.SECRET_GENERIC,
            resource_name=secretname,
            namespace=namespace,
            dry_run=dry_run,
        )
        if not dry_run:
            self.kube_interface.set_label(
                resource_type=KubernetesResourceType.SERVICEACCOUNT,
                resource_name=username,
                label=f"{MANAGED_BY_LABELNAME}={SPARK8S_LABEL}",
                namespace=namespace,
            )
            self.kube_interface.set_label(
                resource_type=KubernetesResourceType.ROLE,
                resource_name=rolename,
                label=f"{MANAGED_BY_LABELNAME}={SPARK8S_LABEL}",
                namespace=namespace,
            )
            self.kube_interface.set_label(
                resource_type=KubernetesResourceType.ROLEBINDING,
                resource_name=rolebindingname,
                label=f"{MANAGED_BY_LABELNAME}={SPARK8S_LABEL}",
                namespace=namespace,
            )
            if service_account.primary is True:
                self.set_primary(account_id=account_id, namespace=namespace)

            if len(service_account.extra_confs) > 0:
                self.set_configurations(
                    account_id=account_id, configurations=configurations
                )

        manifests = [sa_manifest, role_manifest, role_binding_manifest, secret_manifest]
        return "---\n".join(manifests)

    def _create_account_secret(self, service_account: ServiceAccount):
        """Create the secret that will contain the user configurations."""
        secret_name = self._get_secret_name(service_account.name)

        manifest = self.kube_interface.create(
            KubernetesResourceType.SECRET_GENERIC,
            secret_name,
            namespace=service_account.namespace,
        )
        return manifest

    def _add_account_configuration(
        self,
        service_account: ServiceAccount,
    ):
        """Add service account configuration to the service account."""
        secret_name = self._get_secret_name(service_account.name)

        properties = PropertyFile(
            {
                self._kubernetes_key_serializer.serialize(key): value
                for key, value in service_account.extra_confs.props.items()
            }
        )

        # delete secret content
        self.kube_interface.delete_secret_content(
            secret_name,
            namespace=service_account.namespace,
        )

        # add configurations to secrets
        self.kube_interface.add_secret_content(
            secret_name,
            service_account.namespace,
            properties,
        )

    def set_configurations(self, account_id: str, configurations: PropertyFile) -> str:
        """Set a new service account configuration for the provided service account id.

        Args:
            account_id: account id for which configuration ought to be set
            configurations: PropertyFile representing the new configuration to be stored
        """
        namespace, name = account_id.split(":")
        self._add_account_configuration(
            ServiceAccount(
                name=name,
                namespace=namespace,
                api_server=self.kube_interface.api_server,
                extra_confs=configurations,
            )
        )

        return account_id

    def delete(self, account_id: str) -> str:
        """Delete the service account associated with the provided id.

        Args:
            account_id: service account id to be deleted
        """
        namespace, name = account_id.split(":")

        rolename = name + "-role"
        rolebindingname = name + "-role-binding"

        if not self.kube_interface.exists(
            KubernetesResourceType.SERVICEACCOUNT, name, namespace=namespace
        ):
            raise AccountNotFound(name)

        try:
            self.kube_interface.delete(
                KubernetesResourceType.SERVICEACCOUNT, name, namespace=namespace
            )
        except Exception as e:
            self.logger.debug(e)

        try:
            self.kube_interface.delete(
                KubernetesResourceType.ROLE, rolename, namespace=namespace
            )
        except Exception as e:
            self.logger.debug(e)

        try:
            self.kube_interface.delete(
                KubernetesResourceType.ROLEBINDING, rolebindingname, namespace=namespace
            )
        except Exception as e:
            self.logger.debug(e)

        try:
            self.kube_interface.delete(
                KubernetesResourceType.SECRET,
                self._get_secret_name(name),
                namespace=namespace,
            )
        except Exception as e:
            self.logger.debug(e)

        return account_id

    def get(self, account_id: str) -> ServiceAccount | None:
        """Get service account."""
        namespace, username = account_id.split(":")
        try:
            service_account_raw = self.kube_interface.get_service_account(
                username, namespace
            )
        except K8sResourceNotFound:
            return None
        return self._build_service_account_from_raw(service_account_raw["metadata"])
