"""Kube interface backed by the kubectl CLI command."""

from __future__ import annotations

import base64
import json
import os
import subprocess
from functools import cached_property
from typing import Any

import yaml
from lightkube import codecs
from typing_extensions import deprecated

from spark8t.domain import (
    Defaults,
    KubernetesResourceType,
)
from spark8t.exceptions import K8sResourceNotFound
from spark8t.kube_interface.base import AbstractKubeInterface
from spark8t.utils import (
    PropertyFile,
    execute_command_output,
    filter_none,
    listify,
    parse_yaml_shell_output,
    umask_named_temporary_file,
)


@deprecated(
    "The kubectl-backed KubeCtlInterface is now deprecated. Please use the lightkube-backed LightkubeInterface instead."
)
class KubeCtlInterface(AbstractKubeInterface):
    """(DEPRECATED) Class for providing an interface for k8s API needed for the spark client.

    The kubectl backed interface is now deprecated. Please use the lightkube-backed interface instead.
    """

    @cached_property
    def kubectl_cmd(self):
        """Kubectl command."""
        return self.defaults.kubectl_cmd

    def with_context(self, context_name: str) -> KubeCtlInterface:
        """Return a new KubeInterface object using a different context.

        Args:
            context_name: context to be used
        """
        return KubeCtlInterface(self.kube_config_file, self.defaults, context_name)

    def exec(
        self,
        cmd: str,
        namespace: str | None = None,
        context: str | None = None,
        output: str | None = None,
    ) -> str | dict[str, Any]:
        """Execute command provided as a string.

        Args:
            cmd: string command to be executed
            namespace: namespace where the command will be executed. If None the exec command will
                executed with no namespace information
            context: context to be used
            output: format for the output of the command. If "yaml" is used, output is returned as a dictionary.

        Raises:
            CalledProcessError: when the bash command fails and exits with code other than 0

        Returns:
            Output of the command, either parsed as yaml or string
        """
        cmd_list = [self.kubectl_cmd]
        if self.kube_config_file:
            cmd_list += [f"--kubeconfig {self.kube_config_file}"]

        if namespace and "--namespace" not in cmd or "-n" not in cmd:
            cmd_list += [f"--namespace {namespace}"]
        if self.kube_config_file and "--context" not in cmd:
            cmd_list += [f"--context {context or self.context_name}"]

        cmd_list += [cmd, f"-o {output or 'yaml'}"]

        base_cmd = " ".join(cmd_list)

        self.logger.debug(f"Executing command: {base_cmd}")

        return (
            parse_yaml_shell_output(base_cmd)
            if (output is None) or (output == "yaml")
            else execute_command_output(base_cmd)
        )

    def get_service_account(
        self, account_id: str, namespace: str | None = "default"
    ) -> dict[str, Any]:
        """Return the  named service account entry.

        Args:
            namespace: namespace where to look for the service account. Default is 'default'
        """
        cmd = f"get serviceaccount {account_id}"

        try:
            service_account_raw = self.exec(cmd, namespace=namespace)
        except subprocess.CalledProcessError as e:
            if "NotFound" in e.stdout.decode("utf-8"):
                raise K8sResourceNotFound(
                    account_id, KubernetesResourceType.SERVICEACCOUNT
                ) from None
            raise e

        if isinstance(service_account_raw, str):
            raise ValueError(
                f"Error retrieving account id {account_id} in namespace {namespace}"
            )

        self.logger.debug(service_account_raw)
        return service_account_raw

    def delete_secret_content(
        self, secret_name: str, namespace: str | None = None
    ) -> None:
        """Delete the content of the secret name entry.

        Args:
            secret_name: name of the secret.
            namespace: namespace where to look for the service account. Default is 'default'
        """
        if len(self.get_secret(secret_name, namespace)["data"]) == 0:
            self.logger.debug(
                f"Secret: {secret_name} is already empty, no need to delete its content."
            )
            return

        cmd = f'patch secret {secret_name} --type=json -p=\'[{{"op": "remove", "path": "/data" }}]\''

        try:
            service_account_raw = self.exec(cmd, namespace=namespace)
        except subprocess.CalledProcessError as e:
            if "NotFound" in e.stdout.decode("utf-8"):
                raise K8sResourceNotFound(
                    secret_name, KubernetesResourceType.SERVICEACCOUNT
                ) from None
            raise e

        if isinstance(service_account_raw, str):
            raise ValueError(
                f"Error deleting secret content of {secret_name} in namespace {namespace}"
            )

        self.logger.debug(service_account_raw)

    def add_secret_content(
        self,
        secret_name: str,
        namespace: str | None = None,
        configurations: PropertyFile | None = None,
    ) -> None:
        """Add the content of the specified secret.

        Args:
            secret_name: name of the secret
            namespace: namespace where the secret is contained
            configurations: the configuration parameters to add in
        """
        """Add the content of the secret name entry.

        Args:
            secret_name: name of the secret.
            namespace: namespace where to look for the service account. Default is 'default'
        """
        if configurations is None:
            configurations = PropertyFile.empty()

        if len(configurations.props.keys()) == 0:
            self.logger.debug("Empty configuration! Nothing to write")
            return
        cmd = f"patch secret {secret_name} -p='{{\"stringData\": {json.dumps(configurations.props)} }}'"

        try:
            service_account_raw = self.exec(cmd, namespace=namespace)
        except subprocess.CalledProcessError as e:
            if "NotFound" in e.stdout.decode("utf-8"):
                raise K8sResourceNotFound(
                    secret_name, KubernetesResourceType.SERVICEACCOUNT
                ) from None
            raise e

        if isinstance(service_account_raw, str):
            raise ValueError(
                f"Error deleting secret content of {secret_name} in namespace {namespace}"
            )

        self.logger.debug(service_account_raw)

    def get_service_accounts(
        self, namespace: str | None = None, labels: list[str] | None = None
    ) -> list[dict[str, Any]]:
        """Return a list of service accounts, represented as dictionary.

        Args:
            namespace: namespace where to list the service accounts. Default is to None, which will return all service
                       account in all namespaces
            labels: filter to be applied to retrieve service account which match certain labels.
        """
        cmd = "get serviceaccount"

        if labels is not None and len(labels) > 0:
            cmd += " ".join([f" -l {label}" for label in labels])

        if namespace:
            all_service_accounts_raw = self.exec(cmd, namespace=namespace)
        else:
            try:
                all_service_accounts_raw = self.exec(f"{cmd} -A", namespace=None)
            except subprocess.CalledProcessError:
                all_service_accounts_raw = self.exec(cmd, namespace=self.namespace)

        if isinstance(all_service_accounts_raw, str):
            raise ValueError("Malformed output")

        return all_service_accounts_raw["items"]

    def get_secret(
        self, secret_name: str, namespace: str | None = None
    ) -> dict[str, Any]:
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
        except Exception as err:
            raise K8sResourceNotFound(
                secret_name, KubernetesResourceType.SECRET
            ) from err

        if secret is None or len(secret) == 0 or isinstance(secret, str):
            raise K8sResourceNotFound(secret_name, KubernetesResourceType.SECRET)

        result = {}
        # handle empty secret
        if "data" in secret:
            for k, v in secret["data"].items():
                result[k] = base64.b64decode(v).decode("utf-8")

        secret["data"] = result
        return secret

    def set_label(
        self,
        resource_type: str,
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
        self.exec(
            f"label {resource_type} {resource_name} {label}",
            namespace=namespace or self.namespace,
        )

    def remove_label(
        self,
        resource_type: str,
        resource_name: str,
        label: str,
        namespace: str | None = None,
    ):
        """Remove label from to a specified resource."""
        self.exec(
            f"label {resource_type} {resource_name} {label}-",
            namespace=namespace or self.namespace,
        )

    def create(
        self,
        resource_type: str,
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
            extra_args: extra parameters that should be provided when creating the resource. Note that each parameter
                        will be prepended with the -- in the cmd, e.g. {"role": "view"} will translate as
                        --role=view in the command. List of parameter values against a parameter key are also accepted.
                        e.g. {"resource" : ["pods", "configmaps"]} which would translate to something like
                        --resource=pods --resource=configmaps
        """
        dry_run_arg = "--dry-run=client" if dry_run else ""
        if resource_type == KubernetesResourceType.NAMESPACE:
            manifest = self.exec(
                f"create {resource_type} {resource_name} {dry_run_arg}",
                namespace=None,
                output="yaml",
            )
            return yaml.dump(manifest)
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
                )
                with umask_named_temporary_file(
                    mode="w",
                    prefix="role-",
                    suffix=".yaml",
                    dir=os.path.expanduser("~"),
                ) as t:
                    codecs.dump_all_yaml(res, t)
                    manifest = self.exec(
                        f"apply -f {t.name} {dry_run_arg}",
                        namespace=namespace,
                        output="yaml",
                    )
                    return yaml.dump(manifest)
        else:
            # NOTE: removing 'username' to avoid interference with KUBECONFIG
            # ERROR: more than one authentication method found for admin; found [token basicAuth], only one is allowed
            # See for similar:
            # https://stackoverflow.com/questions/53783871/get-error-more-than-one-authentication-method-found-for-tier-two-user-found
            formatted_extra_args = " ".join(
                [
                    f"--{k}={v}"
                    for k, values in extra_args.items()
                    if k != "username"
                    for v in listify(values)
                ]
            )
            manifest = self.exec(
                f"create {resource_type} {resource_name} {formatted_extra_args} {dry_run_arg}",
                namespace=namespace or self.namespace,
                output="yaml",
            )
            return yaml.dump(manifest)

    def delete(
        self, resource_type: str, resource_name: str, namespace: str | None = None
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
        namespace: str | None = None,
    ) -> bool:
        """Check if resource exists."""
        output = self.exec(
            f"get {resource_type} {resource_name} --ignore-not-found",
            namespace=namespace or self.namespace,
        )
        return output is not None

    @classmethod
    def autodetect(
        cls, context_name: str | None = None, defaults: Defaults | None = None
    ) -> "KubeCtlInterface":
        """
        Return a KubeInterface object by auto-parsing the output of the kubectl command.

        Args:
            context_name: context to be used to export the cluster configuration
            defaults: defaults coming from env variable
        """
        if defaults is None:
            defaults = Defaults()
        cmd = defaults.kubectl_cmd

        if context_name:
            cmd += f" --context {context_name}"

        config = parse_yaml_shell_output(f"{cmd} config view --raw --minify -o yaml")

        return KubeCtlInterface(config, defaults=defaults, context_name=context_name)
