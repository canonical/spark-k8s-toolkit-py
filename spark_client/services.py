# mypy: ignore-errors

import base64
import io
import os
import socket
import subprocess
from abc import ABC, ABCMeta, abstractmethod
from enum import Enum
from functools import cached_property
from types import MappingProxyType
from typing import Any, Dict, List, Optional, Type, Union

import yaml
from lightkube import Client, KubeConfig, codecs
from lightkube.core.exceptions import ApiError
from lightkube.core.resource import GlobalResource
from lightkube.models.meta_v1 import ObjectMeta
from lightkube.resources.core_v1 import Namespace, Secret
from lightkube.resources.core_v1 import ServiceAccount as LightKubeServiceAccount
from lightkube.resources.rbac_authorization_v1 import Role, RoleBinding
from lightkube.types import PatchType

from spark_client.domain import (
    Defaults,
    KubernetesResourceType,
    PropertyFile,
    ServiceAccount,
)
from spark_client.exceptions import FormatError, NoAccountFound, NoResourceFound
from spark_client.utils import (
    WithLogging,
    environ,
    filter_none,
    listify,
    parse_yaml_shell_output,
    umask_named_temporary_file,
)


class AbstractKubeInterface(WithLogging, metaclass=ABCMeta):
    """Abstract class for implementing Kubernetes Interface."""

    @abstractmethod
    def with_context(self, context_name: str):
        """Return a new KubeInterface object using a different context.

        Args:
            context_name: context to be used
        """
        pass

    @property
    @abstractmethod
    def kube_config_file(self) -> Union[str, Dict[str, Any]]:
        pass

    @cached_property
    def kube_config(self) -> Dict[str, Any]:
        """Return the kube config file parsed as a dictionary"""
        if isinstance(self.kube_config_file, str):
            with open(self.kube_config_file, "r") as fid:
                return yaml.safe_load(fid)
        else:
            return self.kube_config_file

    @cached_property
    def available_contexts(self) -> List[str]:
        """Return the available contexts present in the kube config file."""
        return [context["name"] for context in self.kube_config["contexts"]]

    @property
    @abstractmethod
    def context_name(self) -> str:
        """Return current context name."""
        pass

    @cached_property
    def context(self) -> Dict[str, str]:
        """Return current context."""
        return [
            context["context"]
            for context in self.kube_config["contexts"]
            if context["name"] == self.context_name
        ][0]

    @cached_property
    def cluster(self) -> Dict:
        """Return current cluster."""
        return [
            cluster["cluster"]
            for cluster in self.kube_config["clusters"]
            if cluster["name"] == self.context["cluster"]
        ][0]

    @cached_property
    def api_server(self):
        """Return current K8s api-server endpoint."""
        return self.cluster["server"]

    @cached_property
    def namespace(self):
        """Return current namespace."""
        return self.context.get("namespace", "default")

    @cached_property
    def user(self):
        """Return current admin user."""
        return self.context.get("user", "default")

    @abstractmethod
    def get_service_account(
        self, account_id: str, namespace: Optional[str] = None
    ) -> Dict[str, Any]:
        pass

    @abstractmethod
    def get_service_accounts(
        self, namespace: Optional[str] = None, labels: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Return a list of service accounts, represented as dictionary.

        Args:
            namespace: namespace where to list the service accounts. Default is to None, which will return all service
                       account in all namespaces
            labels: filter to be applied to retrieve service account which match certain labels.
        """
        pass

    @abstractmethod
    def get_secret(
        self, secret_name: str, namespace: Optional[str] = None
    ) -> Dict[str, Any]:
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
        namespace: Optional[str] = None,
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
        namespace: Optional[str] = None,
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
        namespace: Optional[str] = None,
        **extra_args,
    ):
        """Create a K8s resource.

        Args:
            resource_type: type of the resource to be created, e.g. service account, rolebindings, etc.
            resource_name: name of the resource to be created
            namespace: namespace where the resource is
            extra_args: extra parameters that should be provided when creating the resource. Note that each parameter
                        will be prepended with the -- in the cmd, e.g. {"role": "view"} will translate as
                        --role=view in the command. List of parameter values against a parameter key are also accepted.
                        e.g. {"resource" : ["pods", "configmaps"]} which would translate to something like
                        --resource=pods --resource=configmaps
        """

        pass

    @abstractmethod
    def delete(
        self,
        resource_type: KubernetesResourceType,
        resource_name: str,
        namespace: Optional[str] = None,
    ):
        """Delete a K8s resource.

        Args:
            resource_type: type of the resource to be deleted, e.g. service account, rolebindings, etc.
            resource_name: name of the resource to be deleted
            namespace: namespace where the resource is
        """
        pass

    @abstractmethod
    def exists(
        self,
        resource_type: KubernetesResourceType,
        resource_name: str,
        namespace: Optional[str] = None,
    ) -> bool:
        """Check if a K8s resource exists.

        Args:
            resource_type: type of the resource to be deleted, e.g. service account, rolebindings, etc.
            resource_name: name of the resource to be deleted
            namespace: namespace where the resource is
        """
        pass

    def select_by_master(self, master: str):
        api_servers_clusters = {
            cluster["name"]: cluster["cluster"]["server"]
            for cluster in self.kube_config["clusters"]
        }

        self.logger.debug(f"Clusters API: {dict(api_servers_clusters)}")

        contexts_for_api_server = [
            _context["name"]
            for _context in self.kube_config["contexts"]
            if api_servers_clusters[_context["context"]["cluster"]] == master
        ]

        if len(contexts_for_api_server) == 0:
            raise NoAccountFound(master)

        self.logger.info(
            f"Contexts on api server {master}: {', '.join(contexts_for_api_server)}"
        )

        return (
            self
            if self.context_name in contexts_for_api_server
            else self.with_context(contexts_for_api_server[0])
        )


class LightKube(AbstractKubeInterface):
    _obj_mapping: dict[KubernetesResourceType, Type[GlobalResource]] = MappingProxyType(
        {
            KubernetesResourceType.ROLE: Role,
            KubernetesResourceType.SERVICEACCOUNT: LightKubeServiceAccount,
            KubernetesResourceType.SECRET: Secret,
            KubernetesResourceType.ROLEBINDING: RoleBinding,
            KubernetesResourceType.SECRET_GENERIC: Secret,
            KubernetesResourceType.NAMESPACE: Namespace,
        }
    )

    def __init__(
        self,
        kube_config_file: Union[str, Dict[str, Any]],
        defaults: Defaults,
        context_name: Optional[str] = None,
    ):
        """Initialise a KubeInterface class from a kube config file.

        Args:
            kube_config_file: kube config path
            context_name: name of the context to be used
        """
        self._kube_config_file = kube_config_file
        self._context_name = context_name
        self.config = KubeConfig.from_file(self.kube_config_file)

        self.defaults = defaults

        if context_name:
            self.client = Client(config=self.config.get(context_name=context_name))
        else:
            self.client = Client(config=self.config.get())

    @property
    def kube_config_file(self) -> Union[str, Dict[str, Any]]:
        """Return the kube config file name"""
        return self._kube_config_file

    def with_context(self, context_name: str):
        """Return a new KubeInterface object using a different context.

        Args:
            context_name: context to be used
        """
        return LightKube(self.kube_config_file, self.defaults, context_name)

    @property
    def context_name(self) -> str:
        """Return current context name."""
        return (
            self.kube_config["current-context"]
            if self._context_name is None
            else self._context_name
        )

    def get_service_account(
        self, account_id: str, namespace: Optional[str] = None
    ) -> Dict[str, Any]:
        """Return the  named service account entry.

        Args:
            namespace: namespace where to look for the service account. Default is 'default'
        """

        with io.StringIO() as buffer:
            codecs.dump_all_yaml(
                [
                    self.client.get(
                        res=LightKubeServiceAccount,
                        name=account_id,
                        namespace=namespace,
                    )
                ],
                buffer,
            )
            buffer.seek(0)
            return yaml.safe_load(buffer)

    def get_service_accounts(
        self, namespace: Optional[str] = None, labels: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Return a list of service accounts, represented as dictionary.

        Args:
            namespace: namespace where to list the service accounts. Default is to None, which will return all service
                       account in all namespaces
            labels: filter to be applied to retrieve service account which match certain labels.
        """
        labels_to_pass = dict()
        if labels:
            for entry in labels:
                k, v = PropertyFile.parse_property_line(entry)
                labels_to_pass[k] = v

        if not namespace:
            namespace = "default"

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
            return list(yaml.safe_load_all(buffer))

    def get_secret(
        self, secret_name: str, namespace: Optional[str] = None
    ) -> Dict[str, Any]:
        """Return the data contained in the specified secret.

        Args:
            secret_name: name of the secret
            namespace: namespace where the secret is contained
        """

        with io.StringIO() as buffer:
            codecs.dump_all_yaml(
                [self.client.get(res=Secret, namespace=namespace, name=secret_name)],
                buffer,
            )
            buffer.seek(0)
            secret = yaml.safe_load(buffer)

            result = dict()
            for k, v in secret["data"].items():
                result[k] = base64.b64decode(v).decode("utf-8")

            secret["data"] = result
            return secret

    def set_label(
        self,
        resource_type: KubernetesResourceType,
        resource_name: str,
        label: str,
        namespace: Optional[str] = None,
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
        namespace: Optional[str] = None,
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

    def create_property_file_entries(self, property_file_name) -> Dict[str, str]:
        entries = dict()
        props = PropertyFile.read(property_file_name).props
        for k in props:
            entries[k] = base64.b64encode(str(props[k]).encode("ascii"))
        return props

    def create(
        self,
        resource_type: KubernetesResourceType,
        resource_name: str,
        namespace: Optional[str] = None,
        **extra_args,
    ):
        """Create a K8s resource.

        Args:
            resource_type: type of the resource to be created, e.g. service account, rolebindings, etc.
            resource_name: name of the resource to be created
            namespace: namespace where the resource is
            extra_args: extra parameters that should be provided when creating the resource. Note that each parameter
                        will be prepended with the -- in the cmd, e.g. {"role": "view"} will translate as
                        --role=view in the command. List of parameter values against a parameter key are also accepted.
                        e.g. {"resource" : ["pods", "configmaps"]} which would translate to something like
                        --resource=pods --resource=configmaps
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
                        "metadata": {"name": resource_name, "namespace": namespace},
                        "stringData": self.create_property_file_entries(
                            extra_args["from-env-file"]
                        ),
                    }
                )
            )
        elif resource_type == KubernetesResourceType.NAMESPACE:
            self.client.create(Namespace(metadata=ObjectMeta(name=resource_name)))
            return
        else:
            raise NotImplementedError(
                f"Label setting for resource name {resource_type} not supported yet."
            )

        self.client.create(obj=res, name=resource_name, namespace=namespace)

    def delete(
        self,
        resource_type: KubernetesResourceType,
        resource_name: str,
        namespace: Optional[str] = None,
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
        namespace: Optional[str] = None,
    ) -> bool:
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
            if "not found" in e.status.message:
                return False
            raise e


class KubeInterface(AbstractKubeInterface):
    """Class for providing an interface for k8s API needed for the spark client."""

    def __init__(
        self,
        kube_config_file: Union[str, Dict[str, Any]],
        context_name: Optional[str] = None,
        kubectl_cmd: str = "kubectl",
    ):
        """Initialise a KubeInterface class from a kube config file.

        Args:
            kube_config_file: kube config path
            context_name: name of the context to be used
            kubectl_cmd: path to the kubectl command to be used to interact with the K8s API
        """
        self._kube_config_file = kube_config_file
        self._context_name = context_name
        self.kubectl_cmd = kubectl_cmd

    @property
    def kube_config_file(self) -> Union[str, Dict[str, Any]]:
        """Return the kube config file name"""
        return self._kube_config_file

    @property
    def context_name(self) -> str:
        """Return current context name."""
        return (
            self.kube_config["current-context"]
            if self._context_name is None
            else self._context_name
        )

    def with_context(self, context_name: str):
        """Return a new KubeInterface object using a different context.

        Args:
            context_name: context to be used
        """
        return KubeInterface(self.kube_config_file, context_name, self.kubectl_cmd)

    def with_kubectl_cmd(self, kubectl_cmd: str):
        """Return a new KubeInterface object using a different kubectl command.

        Args:
            kubectl_cmd: path to the kubectl command to be used
        """
        return KubeInterface(self.kube_config_file, self.context_name, kubectl_cmd)

    def exec(
        self,
        cmd: str,
        namespace: Optional[str] = None,
        context: Optional[str] = None,
        output: Optional[str] = None,
    ) -> Union[str, Dict[str, Any]]:
        """Execute command provided as a string.

        Args:
            cmd: string command to be executed
            namespace: namespace where the command will be executed. If None the exec command will
                executed with no namespace information
            context: context to be used
            output: format for the output of the command. If "yaml" is used, output is returned as a dictionary.
        """

        base_cmd = f"{self.kubectl_cmd} --kubeconfig {self.kube_config_file} "

        if namespace and "--namespace" not in cmd or "-n" not in cmd:
            base_cmd += f" --namespace {namespace} "
        if "--context" not in cmd:
            base_cmd += f" --context {context or self.context_name} "

        base_cmd += f"{cmd} -o {output or 'yaml'} "

        self.logger.debug(f"Executing command: {base_cmd}")

        return (
            parse_yaml_shell_output(base_cmd)
            if (output is None) or (output == "yaml")
            else subprocess.check_output(base_cmd, shell=True, stderr=None).decode(
                "utf-8"
            )
        )

    def get_service_account(
        self, account_id: str, namespace: str = "default"
    ) -> Dict[str, Any]:
        """Return the  named service account entry.

        Args:
            namespace: namespace where to look for the service account. Default is 'default'
        """

        cmd = f"get serviceaccount {account_id} -n {namespace}"

        service_account_raw = self.exec(cmd, namespace=self.namespace)

        if isinstance(service_account_raw, str):
            raise ValueError(
                f"Error retrieving account id {account_id} in namespace {namespace}"
            )

        self.logger.warning(service_account_raw)

        return service_account_raw

    def get_service_accounts(
        self, namespace: Optional[str] = None, labels: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Return a list of service accounts, represented as dictionary.

        Args:
            namespace: namespace where to list the service accounts. Default is to None, which will return all service
                       account in all namespaces
            labels: filter to be applied to retrieve service account which match certain labels.
        """
        cmd = "get serviceaccount"

        if labels is not None and len(labels) > 0:
            cmd += " ".join([f" -l {label}" for label in labels])

        namespace = " -A" if namespace is None else f" -n {namespace}"

        all_service_accounts_raw = self.exec(cmd + namespace, namespace=None)

        if isinstance(all_service_accounts_raw, str):
            raise ValueError("Malformed output")

        return all_service_accounts_raw["items"]

    def get_secret(
        self, secret_name: str, namespace: Optional[str] = None
    ) -> Dict[str, Any]:
        """Return the data contained in the specified secret.

        Args:
            secret_name: name of the secret
            namespace: namespace where the secret is contained
        """

        try:
            secret = self.exec(
                f"get secret {secret_name} --ignore-not-found",
                namespace=namespace or self.namespace,
            )
        except Exception:
            raise NoResourceFound(secret_name)

        if secret is None or len(secret) == 0 or isinstance(secret, str):
            raise NoResourceFound(secret_name)

        result = dict()
        for k, v in secret["data"].items():
            # k1 = k.replace(".", "\\.")
            # value = self.kube_interface.exec(f"get secret {secret_name}", output=f"jsonpath='{{.data.{k1}}}'")
            result[k] = base64.b64decode(v).decode("utf-8")

        secret["data"] = result
        return secret

    def set_label(
        self,
        resource_type: str,
        resource_name: str,
        label: str,
        namespace: Optional[str] = None,
    ):
        """Set label to a specified resource (type and name).

        Args:
            resource_type: type of the resource to be labeled, e.g. service account, rolebindings, etc.
            resource_name: name of the resource to be labeled
            namespace: namespace where the resource is
        """
        self.exec(
            f"label {resource_type} {resource_name} {label}",
            namespace=namespace or self.namespace,
        )

    def remove_label(
        self,
        resource_type: str,
        resource_name: str,
        label: str,
        namespace: Optional[str] = None,
    ):
        self.exec(
            f"label {resource_type} {resource_name} {label}-",
            namespace=namespace or self.namespace,
        )

    def create(
        self,
        resource_type: str,
        resource_name: str,
        namespace: Optional[str] = None,
        **extra_args,
    ):
        """Create a K8s resource.

        Args:
            resource_type: type of the resource to be created, e.g. service account, rolebindings, etc.
            resource_name: name of the resource to be created
            namespace: namespace where the resource is
            extra_args: extra parameters that should be provided when creating the resource. Note that each parameter
                        will be prepended with the -- in the cmd, e.g. {"role": "view"} will translate as
                        --role=view in the command. List of parameter values against a parameter key are also accepted.
                        e.g. {"resource" : ["pods", "configmaps"]} which would translate to something like
                        --resource=pods --resource=configmaps
        """
        if resource_type == KubernetesResourceType.NAMESPACE:
            self.exec(
                f"create {resource_type} {resource_name}", namespace=None, output="name"
            )
        else:
            formatted_extra_args = " ".join(
                [
                    f"--{k}={v}"
                    for k, values in extra_args.items()
                    for v in listify(values)
                ]
            )
            self.exec(
                f"create {resource_type} {resource_name} {formatted_extra_args}",
                namespace=namespace or self.namespace,
                output="name",
            )

    def delete(
        self, resource_type: str, resource_name: str, namespace: Optional[str] = None
    ):
        """Delete a K8s resource.

        Args:
            resource_type: type of the resource to be deleted, e.g. service account, rolebindings, etc.
            resource_name: name of the resource to be deleted
            namespace: namespace where the resource is
        """
        self.exec(
            f"delete {resource_type} {resource_name} --ignore-not-found",
            namespace=namespace or self.namespace,
            output="name",
        )

    def exists(
        self,
        resource_type: KubernetesResourceType,
        resource_name: str,
        namespace: Optional[str] = None,
    ) -> bool:
        output = self.exec(
            f"get {resource_type} {resource_name} --ignore-not-found",
            namespace=namespace or self.namespace,
        )
        return output is not None

    @classmethod
    def autodetect(
        cls, context_name: Optional[str] = None, kubectl_cmd: str = "kubectl"
    ) -> "KubeInterface":
        """
        Return a KubeInterface object by auto-parsing the output of the kubectl command.

        Args:
            context_name: context to be used to export the cluster configuration
            kubectl_cmd: path to the kubectl command to be used to interact with the K8s API
        """

        cmd = kubectl_cmd

        if context_name:
            cmd += f" --context {context_name}"

        config = parse_yaml_shell_output(f"{cmd} config view --minify -o yaml")

        return KubeInterface(config, context_name=context_name, kubectl_cmd=kubectl_cmd)

    def select_by_master(self, master: str):
        api_servers_clusters = {
            cluster["name"]: cluster["cluster"]["server"]
            for cluster in self.kube_config["clusters"]
        }

        self.logger.debug(f"Clusters API: {dict(api_servers_clusters)}")

        contexts_for_api_server = [
            _context["name"]
            for _context in self.kube_config["contexts"]
            if api_servers_clusters[_context["context"]["cluster"]] == master
        ]

        if len(contexts_for_api_server) == 0:
            raise NoAccountFound(master)

        self.logger.info(
            f"Contexts on api server {master}: {', '.join(contexts_for_api_server)}"
        )

        return (
            self
            if self.context_name in contexts_for_api_server
            else self.with_context(contexts_for_api_server[0])
        )


class AbstractServiceAccountRegistry(WithLogging, ABC):
    """Abstract class for implementing service that manages spark ServiceAccount resources."""

    @abstractmethod
    def all(self, namespace: Optional[str] = None) -> List["ServiceAccount"]:
        """Return all existing service accounts."""
        pass

    @abstractmethod
    def create(self, service_account: ServiceAccount) -> str:
        """Create a new service account and return ids associated id.

        Args:
            service_account: ServiceAccount to be stored in the registry
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
    def set_primary(self, account_id: str) -> Optional[str]:
        """Set the primary account to the one related to the provided account id.

        Args:
            account_id: account id to be elected as new primary account
        """
        pass

    def get_primary(self) -> Optional[ServiceAccount]:
        """Return the primary service account. None is there is no primary service account."""
        all_accounts = self.all()

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
    def get(self, account_id: str) -> Optional[ServiceAccount]:
        """Return the service account associated with the provided account id. None if no account was found.

        Args:
            account_id: account id to be used for retrieving the service account.
        """
        pass


class K8sServiceAccountRegistry(AbstractServiceAccountRegistry):
    """Class implementing a ServiceAccountRegistry, based on K8s."""

    def __init__(self, kube_interface: AbstractKubeInterface):
        self.kube_interface = kube_interface

    SPARK_MANAGER_LABEL = "app.kubernetes.io/managed-by"
    PRIMARY_LABEL = "app.kubernetes.io/spark-client-primary"

    def all(self, namespace: Optional[str] = None) -> List["ServiceAccount"]:
        """Return all existing service accounts."""
        service_accounts = self.kube_interface.get_service_accounts(
            namespace=namespace, labels=[f"{self.SPARK_MANAGER_LABEL}=spark-client"]
        )
        return [
            self._build_service_account_from_raw(raw["metadata"])
            for raw in service_accounts
        ]

    @staticmethod
    def _get_secret_name(name):
        return f"spark-client-sa-conf-{name}"

    def _retrieve_account_configurations(
        self, name: str, namespace: str
    ) -> PropertyFile:
        secret_name = self._get_secret_name(name)

        try:
            secret = self.kube_interface.get_secret(secret_name, namespace=namespace)[
                "data"
            ]
        except Exception:
            return PropertyFile.empty()

        return PropertyFile(secret)

    def _build_service_account_from_raw(self, metadata: Dict[str, Any]):
        name = metadata["name"]
        namespace = metadata["namespace"]
        primary = self.PRIMARY_LABEL in metadata["labels"]

        return ServiceAccount(
            name=name,
            namespace=namespace,
            primary=primary,
            api_server=self.kube_interface.api_server,
            extra_confs=self._retrieve_account_configurations(name, namespace),
        )

    def set_primary(self, account_id: str) -> Optional[str]:
        """Set the primary account to the one related to the provided account id.

        Args:
            account_id: account id to be elected as new primary account
        """

        # Relabeling primary
        primary_account = self.get_primary()

        if primary_account is not None:
            self.kube_interface.remove_label(
                KubernetesResourceType.SERVICEACCOUNT,
                primary_account.name,
                f"{self.PRIMARY_LABEL}",
                primary_account.namespace,
            )
            self.kube_interface.remove_label(
                KubernetesResourceType.ROLEBINDING,
                f"{primary_account.name}-role-binding",
                f"{self.PRIMARY_LABEL}",
                primary_account.namespace,
            )

        service_account = self.get(account_id)

        if service_account is None:
            raise NoAccountFound(account_id)

        self.kube_interface.set_label(
            KubernetesResourceType.SERVICEACCOUNT,
            service_account.name,
            f"{self.PRIMARY_LABEL}=True",
            service_account.namespace,
        )
        self.kube_interface.set_label(
            KubernetesResourceType.ROLEBINDING,
            f"{service_account.name}-role-binding",
            f"{self.PRIMARY_LABEL}=True",
            service_account.namespace,
        )

        return account_id

    def create(self, service_account: ServiceAccount) -> str:
        """Create a new service account and return ids associated id.

        Args:
            service_account: ServiceAccount to be stored in the registry
        """
        rolename = service_account.name + "-role"
        rolebindingname = service_account.name + "-role-binding"

        self.kube_interface.create(
            KubernetesResourceType.SERVICEACCOUNT,
            service_account.name,
            namespace=service_account.namespace,
        )
        self.kube_interface.create(
            KubernetesResourceType.ROLE,
            rolename,
            namespace=service_account.namespace,
            **{
                "resource": ["pods", "configmaps", "services"],
                "verb": ["create", "get", "list", "watch", "delete"],
            },
        )
        self.kube_interface.create(
            KubernetesResourceType.ROLEBINDING,
            rolebindingname,
            namespace=service_account.namespace,
            **{"role": rolename, "serviceaccount": service_account.id},
        )

        self.kube_interface.set_label(
            KubernetesResourceType.SERVICEACCOUNT,
            service_account.name,
            f"{self.SPARK_MANAGER_LABEL}=spark-client",
            namespace=service_account.namespace,
        )
        self.kube_interface.set_label(
            KubernetesResourceType.ROLE,
            rolename,
            f"{self.SPARK_MANAGER_LABEL}=spark-client",
            namespace=service_account.namespace,
        )
        self.kube_interface.set_label(
            KubernetesResourceType.ROLEBINDING,
            rolebindingname,
            f"{self.SPARK_MANAGER_LABEL}=spark-client",
            namespace=service_account.namespace,
        )

        if service_account.primary is True:
            self.set_primary(service_account.id)

        if len(service_account.extra_confs) > 0:
            self.set_configurations(service_account.id, service_account.extra_confs)

        return service_account.id

    def _create_account_configuration(self, service_account: ServiceAccount):
        secret_name = self._get_secret_name(service_account.name)

        try:
            self.kube_interface.delete(
                KubernetesResourceType.SECRET,
                secret_name,
                namespace=service_account.namespace,
            )
        except Exception:
            pass

        with umask_named_temporary_file(
            mode="w", prefix="spark-dynamic-conf-k8s-", suffix=".conf"
        ) as t:
            self.logger.debug(
                f"Spark dynamic props available for reference at {t.name}\n"
            )

            service_account.extra_confs.write(t.file)

            t.flush()

            self.kube_interface.create(
                KubernetesResourceType.SECRET_GENERIC,
                secret_name,
                namespace=service_account.namespace,
                **{"from-env-file": str(t.name)},
            )

    def set_configurations(self, account_id: str, configurations: PropertyFile) -> str:
        """Set a new service account configuration for the provided service account id.

        Args:
            account_id: account id for which configuration ought to be set
            configurations: PropertyFile representing the new configuration to be stored
        """

        namespace, name = account_id.split(":")

        self._create_account_configuration(
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

    def get(self, account_id: str) -> Optional[ServiceAccount]:
        namespace, username = account_id.split(":")
        service_account_raw = self.kube_interface.get_service_account(
            username, namespace
        )
        return self._build_service_account_from_raw(service_account_raw["metadata"])


class InMemoryAccountRegistry(AbstractServiceAccountRegistry):
    def __init__(self, cache: Dict[str, ServiceAccount]):
        self.cache = cache

        self._consistency_check()

    def _consistency_check(self):
        primaries = [account for account in self.all() if account.primary is True]

        if len(primaries) > 1:
            self.logger.warning(
                "There exists more than one primary in the service account registry."
            )

    def all(self, namespace: Optional[str] = None) -> List["ServiceAccount"]:
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
            [account.primary for account in self.all()]
        ):
            self.logger.info(
                "Primary service account provided. Switching primary account from account"
            )
            for account_id, account in self.cache.items():
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

    def set_primary(self, account_id: str) -> str:
        """Set the primary account to the one related to the provided account id.

        Args:
            account_id: account id to be elected as new primary account
        """
        if account_id not in self.cache.keys():
            raise NoAccountFound(account_id)

        if any([account.primary for account in self.all()]):
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
            raise NoAccountFound(account_id)

        self.cache[account_id].extra_confs = configurations
        return account_id

    def get(self, account_id: str) -> Optional[ServiceAccount]:
        return self.cache[account_id]


def parse_conf_overrides(
    conf_args: List, environ_vars: Dict = dict(os.environ)
) -> PropertyFile:
    """Parse --conf overrides passed to spark-submit

    Args:
        conf_args: list of all --conf 'k1=v1' type args passed to spark-submit.
            Note v1 expression itself could be containing '='
        environ_vars: dictionary with environment variables as key-value pairs
    """
    conf_overrides = dict()
    if conf_args:
        with environ(*os.environ.keys(), **environ_vars):
            for c in conf_args:
                try:
                    kv = c.split("=")
                    k = kv[0]
                    v = "=".join(kv[1:])
                    conf_overrides[k] = os.path.expandvars(v)
                except IndexError:
                    raise FormatError(
                        "Configuration related arguments parsing error. "
                        "Please check input arguments and try again."
                    )
    return PropertyFile(conf_overrides)


class SparkDeployMode(str, Enum):
    CLIENT = "client"
    CLUSTER = "cluster"


class SparkInterface(WithLogging):
    """Class for providing interfaces for spark commands."""

    def __init__(
        self,
        service_account: ServiceAccount,
        kube_interface: AbstractKubeInterface,
        defaults: Defaults,
    ):
        """Initialise spark for a given service account.

        Args:
            service_account: spark ServiceAccount to be used for executing spark on k8s
            defaults: Defaults class containing relevant default settings.
        """
        self.service_account = service_account
        self.kube_interface = kube_interface
        self.defaults = defaults

    @staticmethod
    def _read_properties_file(namefile: Optional[str]) -> PropertyFile:
        return (
            PropertyFile.read(namefile)
            if namefile is not None
            else PropertyFile.empty()
        )

    @staticmethod
    def _generate_properties_file_from_arguments(confs: List[str]):
        if not confs:
            return PropertyFile({})

        return PropertyFile(
            dict(PropertyFile.parse_property_line(line) for line in confs)
        )

    def spark_submit(
        self,
        deploy_mode: SparkDeployMode,
        confs: List[str],
        cli_property: Optional[str],
        extra_args: List[str],
    ):
        """Submit a spark job.

        Args:
            deploy_mode: "client" or "cluster" depending where the driver will run, locally or on the k8s cluster
                         respectively
            confs: list of extra configuration provided via command line
            cli_property: property-file path provided via command line
            extra_args: extra arguments provided to the spark submit command
        """
        with umask_named_temporary_file(
            mode="w", prefix="spark-conf-", suffix=".conf"
        ) as t:
            self.logger.debug(f"Spark props available for reference at {t.name}\n")

            (
                self._read_properties_file(self.defaults.static_conf_file)
                + self.service_account.configurations
                + self._read_properties_file(self.defaults.env_conf_file)
                + self._read_properties_file(cli_property)
                + self._generate_properties_file_from_arguments(confs)
            ).write(t.file)

            t.flush()

            submit_args = [
                f"--master k8s://{self.service_account.api_server}",
                f"--deploy-mode {deploy_mode}",
                f"--properties-file {t.name}",
            ] + extra_args

            submit_cmd = f"{self.defaults.spark_submit} {' '.join(submit_args)}"

            self.logger.debug(submit_cmd)
            with environ(KUBECONFIG=self.kube_interface.kube_config_file):
                os.system(submit_cmd)

    def spark_shell(
        self, confs: List[str], cli_property: Optional[str], extra_args: List[str]
    ):
        """Start an interactinve spark shell.

        Args:
            confs: list of extra configuration provided via command line
            cli_property: property-file path provided via command line
            extra_args: extra arguments provided to spark shell
        """

        with umask_named_temporary_file(
            mode="w", prefix="spark-conf-", suffix=".conf"
        ) as t:
            self.logger.debug(f"Spark props available for reference at {t.name}\n")

            conf = (
                self._read_properties_file(self.defaults.static_conf_file)
                + PropertyFile(
                    {
                        "spark.driver.extraJavaOptions": f"-Dscala.shell.histfile={self.defaults.scala_history_file}"
                    }
                )
                + self.service_account.configurations
                + self._read_properties_file(self.defaults.env_conf_file)
                + self._read_properties_file(cli_property)
                + self._generate_properties_file_from_arguments(confs)
            )

            conf = self.prefix_optional_detected_driver_host(conf)

            if "spark.driver.host" not in conf.props:
                raise ValueError(
                    "Please specify spark.driver.host configuration property"
                )

            conf.write(t.file)

            t.flush()

            submit_args = [
                f"--master k8s://{self.service_account.api_server}",
                f"--properties-file {t.name}",
            ] + extra_args

            submit_cmd = f"{self.defaults.spark_shell} {' '.join(submit_args)}"

            self.logger.debug(submit_cmd)
            with environ(KUBECONFIG=self.kube_interface.kube_config_file):
                os.system(f"touch {self.defaults.scala_history_file}")
                os.system(submit_cmd)

    def pyspark_shell(
        self, confs: List[str], cli_property: Optional[str], extra_args: List[str]
    ):
        """Start an interactinve pyspark shell.

        Args:
            confs: list of extra configuration provided via command line
            cli_property: property-file path provided via command line
            extra_args: extra arguments provided to pyspark
        """

        with umask_named_temporary_file(
            mode="w", prefix="spark-conf-", suffix=".conf"
        ) as t:
            self.logger.debug(f"Spark props available for reference at {t.name}\n")

            conf = (
                self._read_properties_file(self.defaults.static_conf_file)
                + self.service_account.configurations
                + self._read_properties_file(self.defaults.env_conf_file)
                + self._read_properties_file(cli_property)
                + self._generate_properties_file_from_arguments(confs)
            )

            conf = self.prefix_optional_detected_driver_host(conf)

            if "spark.driver.host" not in conf.props:
                raise ValueError(
                    "Please specify spark.driver.host configuration property"
                )

            conf.write(t.file)

            t.flush()

            submit_args = [
                f"--master k8s://{self.service_account.api_server}",
                f"--properties-file {t.name}",
            ] + extra_args

            submit_cmd = f"{self.defaults.pyspark} {' '.join(submit_args)}"

            self.logger.debug(submit_cmd)
            with environ(KUBECONFIG=self.kube_interface.kube_config_file):
                os.system(submit_cmd)

    def prefix_optional_detected_driver_host(self, conf: PropertyFile):
        spark_driver_host = self.detect_host()
        if spark_driver_host:
            return PropertyFile({"spark.driver.host": spark_driver_host}) + conf
        else:
            return conf

    def detect_host(self) -> Any:
        try:
            host = self.service_account.api_server.split(":")[1].split("/")[-1]
            port = (
                self.service_account.api_server.split(":")[2]
                if len(self.service_account.api_server.split(":")) == 3
                else "433"
            )
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((host, int(port)))
            driver_host = s.getsockname()[0]
            s.close()
            return driver_host
        except Exception:
            self.logger.debug(
                f"Driver host autodetection failed for host={host}, port={port}."
            )
            return None
