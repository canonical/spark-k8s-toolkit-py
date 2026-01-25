"""The Kubernetes interface backed by Lightkube Python library."""

from __future__ import annotations

import base64
import io
from functools import cached_property
from types import MappingProxyType
from typing import Any, cast

import yaml
from lightkube import Client, codecs
from lightkube.codecs import AnyResource
from lightkube.core.exceptions import ApiError
from lightkube.models.meta_v1 import ObjectMeta
from lightkube.resources.core_v1 import Namespace, Secret
from lightkube.resources.core_v1 import ServiceAccount as LightKubeServiceAccount
from lightkube.resources.rbac_authorization_v1 import Role, RoleBinding
from lightkube.types import PatchType

from spark8t.domain import (
    KubernetesResourceType,
)
from spark8t.exceptions import K8sResourceNotFound
from spark8t.kube_interface.base import AbstractKubeInterface
from spark8t.literals import GENERATED_BY_LABELNAME, SPARK8S_LABEL
from spark8t.utils import PropertyFile, filter_none


class LightKubeInterface(AbstractKubeInterface):
    """Lightkube interface."""

    _obj_mapping = MappingProxyType(
        {
            KubernetesResourceType.ROLE: Role,
            KubernetesResourceType.SERVICEACCOUNT: LightKubeServiceAccount,
            KubernetesResourceType.SECRET: Secret,
            KubernetesResourceType.ROLEBINDING: RoleBinding,
            KubernetesResourceType.SECRET_GENERIC: Secret,
            KubernetesResourceType.NAMESPACE: Namespace,
        }
    )

    @cached_property
    def client(self):
        """Lightkube client."""
        return Client(config=self.single_config)

    def with_context(self, context_name: str) -> LightKubeInterface:
        """Return a new KubeInterface object using a different context.

        Args:
            context_name: context to be used
        """
        return LightKubeInterface(self.kube_config_file, self.defaults, context_name)

    def get_service_account(
        self, account_id: str, namespace: str | None = None
    ) -> dict[str, Any]:
        """Return the  named service account entry.

        Args:
            namespace: namespace where to look for the service account. Default is 'default'
        """
        try:
            service_account = self.client.get(
                res=LightKubeServiceAccount,
                name=account_id,
                namespace=namespace,
            )
        except ApiError as e:
            if e.status.code == 404:
                raise K8sResourceNotFound(
                    account_id, KubernetesResourceType.SERVICEACCOUNT
                ) from None
            raise e
        except Exception as e:
            raise e

        with io.StringIO() as buffer:
            codecs.dump_all_yaml([service_account], buffer)
            buffer.seek(0)
            return yaml.safe_load(buffer)

    def get_service_accounts(
        self, namespace: str | None = None, labels: list[str] | None = None
    ) -> list[dict[str, Any]]:
        """Return a list of service accounts, represented as dictionary.

        Args:
            namespace: namespace where to list the service accounts. Default is to None, which will return all service
                       account in all namespaces
            labels: filter to be applied to retrieve service account which match certain labels.
        """
        labels_to_pass = {}
        if labels:
            for entry in labels:
                if not PropertyFile.is_line_parsable(entry):
                    continue
                k, v = PropertyFile.parse_property_line(entry)
                labels_to_pass[k] = v

        all_namespaces = []

        if not namespace:
            # means all namespaces
            try:
                iterator = self.client.list(
                    res=Namespace,
                )
                for ns in iterator:
                    all_namespaces.append(ns.metadata.name)
            except Exception:
                all_namespaces.append(self.namespace)

        else:
            all_namespaces = [
                namespace,
            ]

        result = []
        for namespace in all_namespaces:
            with io.StringIO() as buffer:
                codecs.dump_all_yaml(
                    self.client.list(
                        res=LightKubeServiceAccount,
                        namespace=namespace,
                        labels=labels_to_pass,
                    ),
                    buffer,
                )
                buffer.seek(0)
                result += list(yaml.safe_load_all(buffer))

        return result

    def get_secret(
        self, secret_name: str, namespace: str | None = None
    ) -> dict[str, Any]:
        """Return the data contained in the specified secret.

        Args:
            secret_name: name of the secret
            namespace: namespace where the secret is contained
        """
        try:
            with io.StringIO() as buffer:
                codecs.dump_all_yaml(
                    [
                        self.client.get(
                            res=Secret, namespace=namespace, name=secret_name
                        )
                    ],
                    buffer,
                )
                buffer.seek(0)
                secret = yaml.safe_load(buffer)

                result = {}
                if "data" in secret:
                    for k, v in secret["data"].items():
                        result[k] = base64.b64decode(v).decode("utf-8")

                secret["data"] = result
                return secret
        except Exception as err:
            raise K8sResourceNotFound(
                secret_name, KubernetesResourceType.SECRET
            ) from err

    def delete_secret_content(
        self, secret_name: str, namespace: str | None = None
    ) -> None:
        """Delete secret content."""
        if len(self.get_secret(secret_name, namespace)["data"]) == 0:
            self.logger.debug(
                f"Secret: {secret_name} is already empty, no need to delete its content."
            )
            return

        patch = [{"op": "remove", "path": "/data"}]
        self.client.patch(
            res=Secret,
            namespace=namespace,
            name=secret_name,
            obj=patch,
            patch_type=PatchType.JSON,
        )

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
            configurations: the desired configuration to insert
        """
        if configurations is None:
            configurations = PropertyFile.empty()

        patch = {"op": "add", "stringData": configurations.props}
        self.client.patch(res=Secret, namespace=namespace, name=secret_name, obj=patch)

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
        label_fragments = label.split("=")
        patch = {"metadata": {"labels": {label_fragments[0]: label_fragments[1]}}}

        if resource_type == KubernetesResourceType.SERVICEACCOUNT:
            self.client.patch(
                res=LightKubeServiceAccount,
                name=resource_name,
                namespace=namespace,
                obj=patch,
            )
        elif resource_type == KubernetesResourceType.ROLE:
            self.client.patch(
                res=Role, name=resource_name, namespace=namespace, obj=patch
            )
        elif resource_type == KubernetesResourceType.ROLEBINDING:
            self.client.patch(
                res=RoleBinding, name=resource_name, namespace=namespace, obj=patch
            )
        else:
            raise NotImplementedError(
                f"Label setting for resource name {resource_type} not supported yet."
            )

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
            label: label to remove
            namespace: namespace where the resource is
        """
        label_to_remove = f"/metadata/labels/{label.replace('/', '~1')}"
        self.logger.debug(f"Removing label {label_to_remove}")
        patch = [{"op": "remove", "path": label_to_remove}]

        if resource_type == KubernetesResourceType.SERVICEACCOUNT:
            self.client.patch(
                res=LightKubeServiceAccount,
                name=resource_name,
                namespace=namespace,
                obj=patch,
                patch_type=PatchType.JSON,
            )
        elif resource_type == KubernetesResourceType.ROLE:
            self.client.patch(
                res=Role,
                name=resource_name,
                namespace=namespace,
                obj=patch,
                patch_type=PatchType.JSON,
            )
        elif resource_type == KubernetesResourceType.ROLEBINDING:
            self.client.patch(
                res=RoleBinding,
                name=resource_name,
                namespace=namespace,
                obj=patch,
                patch_type=PatchType.JSON,
            )
        else:
            raise NotImplementedError(
                f"Label setting for resource name {resource_type} not supported yet."
            )

    def create_property_file_entries(self, property_file_name) -> dict[str, str]:
        """Create property file entries."""
        entries = {}
        props = PropertyFile.read(property_file_name).props
        for k in props:
            entries[k] = base64.b64encode(str(props[k]).encode("ascii"))
        return props

    def create(
        self,
        resource_type: KubernetesResourceType,
        resource_name: str,
        namespace: str | None = None,
        dry_run: bool = False,
        **extra_args,
    ):
        """Create a K8s resource.

        Args:
            resource_type: type of the resource to be created, e.g. service account, rolebindings, etc.
            resource_name: name of the resource to be created
            namespace: namespace where the resource is
            dry_run: whether to skip actual creation of resources
            extra_args: extra parameters that should be provided when creating the resource. Note that each parameter
                        will be prepended with the -- in the cmd, e.g. {"role": "view"} will translate as
                        --role=view in the command. List of parameter values against a parameter key are also accepted.
                        e.g. {"resource" : ["pods", "configmaps"]} which would translate to something like
                        --resource=pods --resource=configmaps
        Returns:
            A string dump of the YAML manifest of all resources created.
        """
        res = None
        if resource_type == KubernetesResourceType.SERVICEACCOUNT:
            with open(self.defaults.template_serviceaccount) as f:
                res = codecs.load_all_yaml(
                    f,
                    context=filter_none(
                        {
                            "resourcename": resource_name,
                            "namespace": namespace,
                        }
                        | extra_args
                    ),
                ).__getitem__(0)
        elif resource_type == KubernetesResourceType.ROLE:
            with open(self.defaults.template_role) as f:
                res = codecs.load_all_yaml(
                    f,
                    context=filter_none(
                        {
                            "resourcename": resource_name,
                            "namespace": namespace,
                        }
                        | extra_args
                    ),
                ).__getitem__(0)
        elif resource_type == KubernetesResourceType.ROLEBINDING:
            with open(self.defaults.template_rolebinding) as f:
                res = codecs.load_all_yaml(
                    f,
                    context=filter_none(
                        {
                            "resourcename": resource_name,
                            "namespace": namespace,
                        }
                        | extra_args
                    ),
                ).__getitem__(0)
        elif (
            resource_type == KubernetesResourceType.SECRET
            or resource_type == KubernetesResourceType.SECRET_GENERIC
        ):
            res = Secret.from_dict(
                filter_none(
                    {
                        "apiVersion": "v1",
                        "kind": "Secret",
                        "metadata": {
                            "name": resource_name,
                            "namespace": namespace,
                            "labels": {GENERATED_BY_LABELNAME: SPARK8S_LABEL},
                        },
                    }
                )
            )
        elif resource_type == KubernetesResourceType.NAMESPACE:
            res = cast(AnyResource, Namespace(metadata=ObjectMeta(name=resource_name)))
        else:
            raise NotImplementedError(
                f"Label setting for resource name {resource_type} not supported yet."
            )

        if not dry_run:
            self.client.create(obj=res, name=resource_name, namespace=namespace)
        if res is None:
            return ""
        return codecs.dump_all_yaml([cast(AnyResource, res)])  # mypy: ignore

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
        if resource_type == KubernetesResourceType.SERVICEACCOUNT:
            self.client.delete(
                res=LightKubeServiceAccount, name=resource_name, namespace=namespace
            )
        elif resource_type == KubernetesResourceType.ROLE:
            self.client.delete(res=Role, name=resource_name, namespace=namespace)
        elif resource_type == KubernetesResourceType.ROLEBINDING:
            self.client.delete(res=RoleBinding, name=resource_name, namespace=namespace)
        elif (
            resource_type == KubernetesResourceType.SECRET
            or resource_type == KubernetesResourceType.SECRET_GENERIC
        ):
            self.client.delete(res=Secret, name=resource_name, namespace=namespace)
        elif resource_type == KubernetesResourceType.NAMESPACE:
            self.client.delete(res=Namespace, name=resource_name)
        else:
            raise NotImplementedError(
                f"Label setting for resource name {resource_type} not supported yet."
            )

    def exists(
        self,
        resource_type: KubernetesResourceType,
        resource_name: str,
        namespace: str | None = None,
    ) -> bool:
        """Check if resource exists."""
        try:
            if namespace is None:
                obj = self.client.get(self._obj_mapping[resource_type], resource_name)
            else:
                if resource_type == KubernetesResourceType.NAMESPACE:
                    raise ValueError(
                        "Cannot pass namespace with resource_type Namespace"
                    )
                obj = self.client.get(
                    self._obj_mapping[resource_type], resource_name, namespace=namespace
                )
            return obj is not None

        except ApiError as e:
            if "not found" in str(e.status.message):
                return False
            raise e
