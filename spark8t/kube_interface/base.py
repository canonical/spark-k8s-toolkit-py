"""Abstract class definition for Kubernetes interface."""

from __future__ import annotations

from abc import ABCMeta, abstractmethod
from functools import cached_property
from typing import Any

from lightkube import KubeConfig, SingleConfig
from typing_extensions import Self

from spark8t.domain import Defaults, KubernetesResourceType
from spark8t.exceptions import AccountNotFound
from spark8t.utils import PropertyFile, WithLogging


class AbstractKubeInterface(WithLogging, metaclass=ABCMeta):
    """Abstract class for implementing Kubernetes Interface."""

    def __init__(
        self,
        kube_config_file: str | dict[str, Any] | None,
        defaults: Defaults,
        context_name: str | None = None,
    ):
        """Initialise a KubeInterface class from a kube config file.

        Args:
            kube_config_file: kube config path
            context_name: name of the context to be used
        """
        self.kube_config_file = kube_config_file
        self.defaults = defaults
        self._context_name = context_name

    def with_context(self, context_name: str) -> Self:
        """Return a new KubeInterface object using a different context.

        Args:
            context_name: context to be used
        """
        return type(self)(self.kube_config_file, self.defaults, context_name)

    @cached_property
    def kube_config(self) -> KubeConfig:
        """Return the kube config file parsed as a dictionary."""
        if not self.kube_config_file:
            return KubeConfig.from_env()

        if isinstance(self.kube_config_file, str):
            return KubeConfig.from_file(self.kube_config_file)
        elif isinstance(self.kube_config_file, dict):
            return KubeConfig.from_dict(self.kube_config_file)
        else:
            raise ValueError(
                f"malformed kube_config: type {type(self.kube_config_file)}"
            )

    @cached_property
    def context_name(self) -> str:
        """Interface context name."""
        return self._context_name or self.kube_config.current_context

    @cached_property
    def single_config(self) -> SingleConfig | None:
        """Interface single config."""
        return self.kube_config.get(self.context_name)

    @cached_property
    def api_server(self):
        """Return current K8s api-server endpoint."""
        return self.single_config.cluster.server

    @cached_property
    def namespace(self):
        """Return current namespace."""
        return self.single_config.context.namespace

    @cached_property
    def user(self):
        """Return current admin user."""
        return self.single_config.context.user

    @abstractmethod
    def get_service_account(
        self, account_id: str, namespace: str | None = None
    ) -> dict[str, Any]:
        """Get service account."""
        pass

    @abstractmethod
    def get_service_accounts(
        self, namespace: str | None = None, labels: list[str] | None = None
    ) -> list[dict[str, Any]]:
        """Return a list of service accounts, represented as dictionary.

        Args:
            namespace: namespace where to list the service accounts. Default is to None, which will return all service
                       account in all namespaces
            labels: filter to be applied to retrieve service account which match certain labels.
        """
        pass

    @abstractmethod
    def get_secret(
        self, secret_name: str, namespace: str | None = None
    ) -> dict[str, Any]:
        """Return the data contained in the specified secret.

        Args:
            secret_name: name of the secret
            namespace: namespace where the secret is contained
        """
        pass

    @abstractmethod
    def set_label(
        self,
        resource_type: KubernetesResourceType,
        resource_name: str,
        label: str,
        namespace: str | None = None,
    ):
        """Set label to a specified resource (type and name).

        Args:
            resource_type: type of the resource to be labeled, e.g. service account, rolebindings, etc.
            resource_name: name of the resource to be labeled
            namespace: namespace where the resource is
        """
        pass

    @abstractmethod
    def remove_label(
        self,
        resource_type: KubernetesResourceType,
        resource_name: str,
        label: str,
        namespace: str | None = None,
    ):
        """Remove label to a specified resource (type and name).

        Args:
            resource_type: type of the resource to be labeled, e.g. service account, rolebindings, etc.
            resource_name: name of the resource to be labeled
            label: label to be removed
            namespace: namespace where the resource is
        """
        pass

    @abstractmethod
    def create(
        self,
        resource_type: KubernetesResourceType,
        resource_name: str,
        namespace: str | None = None,
        dry_run: bool = False,
        **extra_args,
    ) -> str:
        """Create a K8s resource.

        Args:
            resource_type: type of the resource to be created, e.g. service account, rolebindings, etc.
            resource_name: name of the resource to be created
            namespace: namespace where the resource is
            dry_run: whether to skip the actual creation of resources
            extra_args: extra parameters that should be provided when creating the resource. Note that each parameter
                        will be prepended with the -- in the cmd, e.g. {"role": "view"} will translate as
                        --role=view in the command. List of parameter values against a parameter key are also accepted.
                        e.g. {"resource" : ["pods", "configmaps"]} which would translate to something like
                        --resource=pods --resource=configmaps
        Returns:
            A string dump of the YAML manifest of all resources created.
        """
        pass

    @abstractmethod
    def delete(
        self,
        resource_type: KubernetesResourceType,
        resource_name: str,
        namespace: str | None = None,
    ):
        """Delete a K8s resource.

        Args:
            resource_type: type of the resource to be deleted, e.g. service account, rolebindings, etc.
            resource_name: name of the resource to be deleted
            namespace: namespace where the resource is
        """
        pass

    def delete_secret_content(
        self, secret_name: str, namespace: str | None = None
    ) -> None:
        """Delete the content of the specified secret.

        Args:
            secret_name: name of the secret
            namespace: namespace where the secret is contained
        """
        pass

    def add_secret_content(
        self,
        secret_name: str,
        namespace: str | None = None,
        configurations: PropertyFile | None = None,
    ) -> None:
        """Delete the content of the specified secret.

        Args:
            secret_name: name of the secret
            namespace: namespace where the secret is contained
        """
        pass

    @abstractmethod
    def exists(
        self,
        resource_type: KubernetesResourceType,
        resource_name: str,
        namespace: str | None = None,
    ) -> bool:
        """Check if a K8s resource exists.

        Args:
            resource_type: type of the resource to be deleted, e.g. service account, rolebindings, etc.
            resource_name: name of the resource to be deleted
            namespace: namespace where the resource is
        """
        pass

    def select_by_master(self, master: str):
        """Get a specific interface."""
        api_servers_clusters = {
            name: cluster.server for name, cluster in self.kube_config.clusters.items()
        }

        self.logger.debug(f"Clusters API: {dict(api_servers_clusters)}")

        contexts_for_api_server = [
            name
            for name, context in self.kube_config.contexts.items()
            if api_servers_clusters[context.cluster] == master
        ]

        if len(contexts_for_api_server) == 0:
            raise AccountNotFound(master)

        self.logger.info(
            f"Contexts on api server {master}: {', '.join(contexts_for_api_server)}"
        )

        return (
            self
            if self.context_name in contexts_for_api_server
            else self.with_context(contexts_for_api_server[0])
        )
