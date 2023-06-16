import base64
import io
import logging
import os
import unittest
import uuid
from unittest import TestCase
from unittest.mock import ANY, patch

import yaml
from lightkube.resources.core_v1 import Secret
from lightkube.resources.core_v1 import ServiceAccount as LightKubeServiceAccount
from lightkube.resources.rbac_authorization_v1 import Role, RoleBinding
from lightkube.types import PatchType
from OpenSSL import crypto

from spark8t.cli import defaults
from spark8t.domain import KubernetesResourceType, PropertyFile, ServiceAccount
from spark8t.literals import MANAGED_BY_LABELNAME, PRIMARY_LABELNAME, SPARK8S_LABEL
from spark8t.services import (
    K8sServiceAccountRegistry,
    KubeInterface,
    LightKube,
    parse_conf_overrides,
)


class TestServices(TestCase):
    @property
    def kubeconfig_file_for_lighkube_unit_tests(self) -> str:
        return "./lightkube_unittest_kubeconfig.yaml"

    def setUp(self) -> None:
        if not os.path.isfile(self.kubeconfig_file_for_lighkube_unit_tests):
            self.generate_kube_config_file(self.kubeconfig_file_for_lighkube_unit_tests)

    def tearDown(self) -> None:
        os.remove(self.kubeconfig_file_for_lighkube_unit_tests)

    def test_conf_expansion_cli(self):
        home_var = "/this/is/my/home"

        parsed_property = parse_conf_overrides(
            ["my-conf=$HOME/folder", "my-other-conf=/this/does/$NOT/change"],
            environ_vars={"HOME": home_var},
        )
        self.assertEqual(parsed_property.props["my-conf"], f"{home_var}/folder")
        self.assertEqual(
            parsed_property.props["my-other-conf"], "/this/does/$NOT/change"
        )

    def test_kube_interface(self):
        # mock logic
        test_id = str(uuid.uuid4())
        username1 = str(uuid.uuid4())
        context1 = str(uuid.uuid4())
        token1 = str(uuid.uuid4())
        username2 = str(uuid.uuid4())
        context2 = str(uuid.uuid4())
        token2 = str(uuid.uuid4())
        username3 = str(uuid.uuid4())
        context3 = str(uuid.uuid4())
        token3 = str(uuid.uuid4())
        test_kubectl_cmd = str(uuid.uuid4())

        kubeconfig_yaml = {
            "apiVersion": "v1",
            "clusters": [
                {
                    "cluster": {
                        "certificate-authority-data": f"{test_id}-1",
                        "server": f"https://0.0.0.0:{test_id}-1",
                    },
                    "name": f"{context1}-cluster",
                },
                {
                    "cluster": {
                        "certificate-authority-data": f"{test_id}-2",
                        "server": f"https://0.0.0.0:{test_id}-2",
                    },
                    "name": f"{context2}-cluster",
                },
                {
                    "cluster": {
                        "certificate-authority-data": f"{test_id}-3",
                        "server": f"https://0.0.0.0:{test_id}-3",
                    },
                    "name": f"{context3}-cluster",
                },
            ],
            "contexts": [
                {
                    "context": {
                        "cluster": f"{context1}-cluster",
                        "user": f"{username1}",
                    },
                    "name": f"{context1}",
                },
                {
                    "context": {
                        "cluster": f"{context2}-cluster",
                        "user": f"{username2}",
                    },
                    "name": f"{context2}",
                },
                {
                    "context": {
                        "cluster": f"{context3}-cluster",
                        "user": f"{username3}",
                    },
                    "name": f"{context3}",
                },
            ],
            "current-context": f"{context2}",
            "kind": "Config",
            "preferences": {},
            "users": [
                {"name": f"{username1}", "user": {"token": f"{token1}"}},
                {"name": f"{username2}", "user": {"token": f"{token2}"}},
                {"name": f"{username3}", "user": {"token": f"{token3}"}},
            ],
        }

        k = KubeInterface(kube_config_file=kubeconfig_yaml)

        self.assertEqual(k.context_name, context2)
        self.assertEqual(k.with_context(context3).context_name, context3)
        self.assertEqual(
            k.with_context(context3).context.get("cluster"), f"{context3}-cluster"
        )
        self.assertEqual(
            k.with_kubectl_cmd(test_kubectl_cmd).kubectl_cmd, test_kubectl_cmd
        )
        self.assertEqual(k.kube_config, kubeconfig_yaml)

        self.assertTrue(context1 in k.available_contexts)
        self.assertTrue(context2 in k.available_contexts)
        self.assertTrue(context3 in k.available_contexts)
        self.assertEqual(len(k.available_contexts), 3)

        current_context = k.context
        self.assertEqual(current_context.get("cluster"), f"{context2}-cluster")
        self.assertEqual(current_context.get("user"), f"{username2}")

        current_cluster = k.cluster
        self.assertEqual(
            current_cluster.get("certificate-authority-data"), f"{test_id}-2"
        )
        self.assertEqual(current_cluster.get("server"), f"https://0.0.0.0:{test_id}-2")

    def cert_gen(
        self,
        emailAddress="emailAddress",
        commonName="commonName",
        countryName="NT",
        localityName="localityName",
        stateOrProvinceName="stateOrProvinceName",
        organizationName="organizationName",
        organizationUnitName="organizationUnitName",
        serialNumber=0,
        validityStartInSeconds=0,
        validityEndInSeconds=10 * 365 * 24 * 60 * 60,
    ) -> str:
        # can look at generated file using openssl:
        # openssl x509 -inform pem -in selfsigned.crt -noout -text
        # create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 4096)
        # create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = countryName
        cert.get_subject().ST = stateOrProvinceName
        cert.get_subject().L = localityName
        # cert.get_subject().O = organizationName  # codespell gives error
        cert.get_subject().OU = organizationUnitName
        cert.get_subject().CN = commonName
        cert.get_subject().emailAddress = emailAddress
        cert.set_serial_number(serialNumber)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(validityEndInSeconds)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, "sha512")

        with io.StringIO() as buffer:
            buffer.write(
                crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8")
            )
            buffer.seek(0)
            return base64.b64encode(buffer.read().encode("ascii")).decode("ascii")

        # with open(CERT_FILE, "wt") as f:
        #     f.write()
        # with open(KEY_FILE, "wt") as f:
        #     f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))

    def generate_kube_config_file(self, kube_config_file_name: str) -> None:
        username1 = "username1"
        username2 = "username2"
        username3 = "username3"
        context1 = "context1"
        context2 = "context2"
        context3 = "context3"

        token1 = str(uuid.uuid4())
        token2 = str(uuid.uuid4())
        token3 = str(uuid.uuid4())
        ca_cert_data = self.cert_gen()

        kubeconfig_yaml = {
            "apiVersion": "v1",
            "clusters": [
                {
                    "cluster": {
                        "certificate-authority-data": f"{ca_cert_data}",
                        "server": "https://0.0.0.0:9090",
                    },
                    "name": f"{context1}-cluster",
                },
                {
                    "cluster": {
                        "certificate-authority-data": f"{ca_cert_data}",
                        "server": "https://0.0.0.1:9090",
                    },
                    "name": f"{context2}-cluster",
                },
                {
                    "cluster": {
                        "certificate-authority-data": f"{ca_cert_data}",
                        "server": "https://0.0.0.2:8080",
                    },
                    "name": f"{context3}-cluster",
                },
            ],
            "contexts": [
                {
                    "context": {
                        "cluster": f"{context1}-cluster",
                        "user": f"{username1}",
                    },
                    "name": f"{context1}",
                },
                {
                    "context": {
                        "cluster": f"{context2}-cluster",
                        "user": f"{username2}",
                    },
                    "name": f"{context2}",
                },
                {
                    "context": {
                        "cluster": f"{context3}-cluster",
                        "user": f"{username3}",
                    },
                    "name": f"{context3}",
                },
            ],
            "current-context": f"{context2}",
            "kind": "Config",
            "preferences": {},
            "users": [
                {"name": f"{username1}", "user": {"token": f"{token1}"}},
                {"name": f"{username2}", "user": {"token": f"{token2}"}},
                {"name": f"{username3}", "user": {"token": f"{token3}"}},
            ],
        }

        with open(kube_config_file_name, "w") as file:
            yaml.dump(kubeconfig_yaml, file)

    def test_lightkube(self):
        # mock logic
        context1 = "context1"
        username2 = "username2"
        context2 = "context2"
        context3 = "context3"

        k = LightKube(
            kube_config_file=self.kubeconfig_file_for_lighkube_unit_tests,
            defaults=defaults,
        )

        self.assertEqual(k.context_name, context2)
        self.assertEqual(k.with_context(context3).context_name, context3)
        self.assertEqual(
            k.with_context(context3).context.get("cluster"), f"{context3}-cluster"
        )

        self.assertTrue(context1 in k.available_contexts)
        self.assertTrue(context2 in k.available_contexts)
        self.assertTrue(context3 in k.available_contexts)
        self.assertEqual(len(k.available_contexts), 3)

        current_context = k.context
        self.assertEqual(current_context.get("cluster"), f"{context2}-cluster")
        self.assertEqual(current_context.get("user"), f"{username2}")

        current_cluster = k.cluster
        self.assertEqual(current_cluster.get("server"), "https://0.0.0.1:9090")

    @patch("lightkube.Client.get")
    def test_lightkube_get_secret(self, mock_lightkube_client_get):
        kubeconfig = self.kubeconfig_file_for_lighkube_unit_tests
        secret_name = str(uuid.uuid4())
        namespace = str(uuid.uuid4())
        conf_key = str(uuid.uuid4())
        conf_value = str(uuid.uuid4())

        def side_effect(*args, **kwargs):
            assert kwargs["name"] == secret_name
            assert kwargs["namespace"] == namespace
            return Secret.from_dict(
                {
                    "apiVersion": "v1",
                    "kind": "Secret",
                    "metadata": {"name": secret_name, "namespace": namespace},
                    "data": {conf_key: base64.b64encode(conf_value.encode("utf-8"))},
                }
            )

        mock_lightkube_client_get.side_effect = side_effect

        k = LightKube(kube_config_file=kubeconfig, defaults=defaults)
        secret_result = k.get_secret(secret_name, namespace)
        self.assertEqual(conf_value, secret_result["data"][conf_key])

    @patch("yaml.safe_load")
    @patch("builtins.open")
    @patch("subprocess.check_output")
    def test_kube_interface_get_secret(
        self, mock_subprocess, mock_open, mock_yaml_safe_load
    ):
        # mock logic
        def side_effect(*args, **kwargs):
            return values[args[0]]

        mock_subprocess.side_effect = side_effect

        test_id = str(uuid.uuid4())
        kubeconfig = str(uuid.uuid4())
        username = str(uuid.uuid4())
        namespace = str(uuid.uuid4())
        secret_name = f"{SPARK8S_LABEL}-sa-conf-{username}"
        context = str(uuid.uuid4())
        token = str(uuid.uuid4())
        conf_key = str(uuid.uuid4())
        conf_value = str(uuid.uuid4())
        conf_value_base64_encoded = base64.b64encode(conf_value.encode("utf-8"))

        kubeconfig_yaml = {
            "apiVersion": "v1",
            "clusters": [
                {
                    "cluster": {
                        "certificate-authority-data": f"{test_id}",
                        "server": f"https://0.0.0.0:{test_id}",
                    },
                    "name": f"{context}-cluster",
                }
            ],
            "contexts": [
                {
                    "context": {"cluster": f"{context}-cluster", "user": f"{username}"},
                    "name": f"{context}",
                }
            ],
            "current-context": f"{context}",
            "kind": "Config",
            "preferences": {},
            "users": [{"name": f"{username}", "user": {"token": f"{token}"}}],
        }

        kubeconfig_yaml_str = yaml.dump(kubeconfig_yaml, sort_keys=False)

        cmd_get_secret = f"kubectl --kubeconfig {kubeconfig}  --namespace {namespace}  --context {context} get secret {secret_name} --ignore-not-found -o yaml "
        output_get_secret_yaml = {
            "apiVersion": "v1",
            "data": {conf_key: conf_value_base64_encoded},
            "kind": "Secret",
            "metadata": {
                "creationTimestamp": "2022-11-21T07:54:51Z",
                "name": f"{SPARK8S_LABEL}-sa-conf-{username}",
                "namespace": namespace,
                "resourceVersion": "292967",
                "uid": "943b82c3-2891-4332-886c-621ef4f4633f",
            },
            "type": "Opaque",
        }
        output_get_secret = yaml.dump(output_get_secret_yaml, sort_keys=False).encode(
            "utf-8"
        )
        values = {
            cmd_get_secret: output_get_secret,
        }

        mock_yaml_safe_load.side_effect = [kubeconfig_yaml, output_get_secret_yaml]

        with patch("builtins.open", mock_open(read_data=kubeconfig_yaml_str)):
            k = KubeInterface(kube_config_file=kubeconfig)
            secret_result = k.get_secret(secret_name, namespace)
            self.assertEqual(conf_value, secret_result["data"][conf_key])

        mock_subprocess.assert_any_call(cmd_get_secret, shell=True, stderr=None)

    @patch("lightkube.Client.patch")
    def test_lightkube_set_label_service_account(self, mock_lightkube_client_patch):
        kubeconfig = self.kubeconfig_file_for_lighkube_unit_tests
        resource_name = str(uuid.uuid4())
        namespace = str(uuid.uuid4())
        label_key = str(uuid.uuid4())
        label_value = str(uuid.uuid4())
        label = f"{label_key}={label_value}"

        mock_lightkube_client_patch.return_value = 0

        k = LightKube(kube_config_file=kubeconfig, defaults=defaults)
        k.set_label("serviceaccount", resource_name, label, namespace)

        patch = {"metadata": {"labels": {label_key: label_value}}}

        mock_lightkube_client_patch.assert_any_call(
            res=LightKubeServiceAccount,
            name=resource_name,
            namespace=namespace,
            obj=patch,
        )

    @patch("lightkube.Client.patch")
    def test_lightkube_set_label_role(self, mock_lightkube_client_patch):
        kubeconfig = self.kubeconfig_file_for_lighkube_unit_tests
        resource_name = str(uuid.uuid4())
        namespace = str(uuid.uuid4())
        label_key = str(uuid.uuid4())
        label_value = str(uuid.uuid4())
        label = f"{label_key}={label_value}"

        def side_effect(*args, **kwargs):
            assert kwargs["name"] == resource_name
            assert kwargs["namespace"] == namespace
            assert kwargs["res"] == Role

        mock_lightkube_client_patch.side_effect = side_effect
        mock_lightkube_client_patch.return_value = 0

        k = LightKube(kube_config_file=kubeconfig, defaults=defaults)
        k.set_label("role", resource_name, label, namespace)

    @patch("lightkube.Client.patch")
    def test_lightkube_set_label_role_binding(self, mock_lightkube_client_patch):
        kubeconfig = self.kubeconfig_file_for_lighkube_unit_tests
        resource_name = str(uuid.uuid4())
        namespace = str(uuid.uuid4())
        label_key = str(uuid.uuid4())
        label_value = str(uuid.uuid4())
        label = f"{label_key}={label_value}"

        def side_effect(*args, **kwargs):
            assert kwargs["name"] == resource_name
            assert kwargs["namespace"] == namespace
            assert kwargs["res"] == RoleBinding

        mock_lightkube_client_patch.side_effect = side_effect
        mock_lightkube_client_patch.return_value = 0

        k = LightKube(kube_config_file=kubeconfig, defaults=defaults)
        k.set_label("rolebinding", resource_name, label, namespace)

    @patch("lightkube.Client.patch")
    def test_lightkube_remove_label_service_account(self, mock_lightkube_client_patch):
        kubeconfig = self.kubeconfig_file_for_lighkube_unit_tests
        resource_name = str(uuid.uuid4())
        namespace = str(uuid.uuid4())
        label_key = str(uuid.uuid4())

        mock_lightkube_client_patch.return_value = 0

        k = LightKube(kube_config_file=kubeconfig, defaults=defaults)
        k.remove_label("serviceaccount", resource_name, label_key, namespace)

        patch = [
            {"op": "remove", "path": f"/metadata/labels/{label_key.replace('/', '~1')}"}
        ]

        # for write_call in mock_lightkube_client_patch.call_args_list:
        #     print('args: {}'.format(write_call[0]))
        #     print('kwargs: {}'.format(write_call[1]))

        mock_lightkube_client_patch.assert_any_call(
            res=LightKubeServiceAccount,
            name=resource_name,
            namespace=namespace,
            obj=patch,
            patch_type=PatchType.JSON,
        )

    @patch("lightkube.Client.patch")
    def test_lightkube_remove_label_role(self, mock_lightkube_client_patch):
        kubeconfig = self.kubeconfig_file_for_lighkube_unit_tests
        resource_name = str(uuid.uuid4())
        namespace = str(uuid.uuid4())
        label_key = str(uuid.uuid4())

        mock_lightkube_client_patch.return_value = 0

        k = LightKube(kube_config_file=kubeconfig, defaults=defaults)
        k.remove_label("role", resource_name, label_key, namespace)

        patch = [
            {"op": "remove", "path": f"/metadata/labels/{label_key.replace('/', '~1')}"}
        ]

        # for write_call in mock_lightkube_client_patch.call_args_list:
        #     print('args: {}'.format(write_call[0]))
        #     print('kwargs: {}'.format(write_call[1]))

        mock_lightkube_client_patch.assert_any_call(
            res=Role,
            name=resource_name,
            namespace=namespace,
            obj=patch,
            patch_type=PatchType.JSON,
        )

    @patch("lightkube.Client.patch")
    def test_lightkube_remove_label_role_binding(self, mock_lightkube_client_patch):
        kubeconfig = self.kubeconfig_file_for_lighkube_unit_tests
        resource_name = str(uuid.uuid4())
        namespace = str(uuid.uuid4())
        label_key = str(uuid.uuid4())

        mock_lightkube_client_patch.return_value = 0

        k = LightKube(kube_config_file=kubeconfig, defaults=defaults)
        k.remove_label("rolebinding", resource_name, label_key, namespace)

        patch = [
            {"op": "remove", "path": f"/metadata/labels/{label_key.replace('/', '~1')}"}
        ]

        # for write_call in mock_lightkube_client_patch.call_args_list:
        #     print('args: {}'.format(write_call[0]))
        #     print('kwargs: {}'.format(write_call[1]))

        mock_lightkube_client_patch.assert_any_call(
            res=RoleBinding,
            name=resource_name,
            namespace=namespace,
            obj=patch,
            patch_type=PatchType.JSON,
        )

    @patch("yaml.safe_load")
    @patch("builtins.open")
    @patch("subprocess.check_output")
    def test_kube_interface_set_label(
        self, mock_subprocess, mock_open, mock_yaml_safe_load
    ):
        # mock logic
        def side_effect(*args, **kwargs):
            return values[args[0]]

        mock_subprocess.side_effect = side_effect

        test_id = str(uuid.uuid4())
        kubeconfig = str(uuid.uuid4())
        username = str(uuid.uuid4())
        namespace = str(uuid.uuid4())
        context = str(uuid.uuid4())
        token = str(uuid.uuid4())
        resource_type = str(uuid.uuid4())
        resource_name = str(uuid.uuid4())
        label = str(uuid.uuid4())

        kubeconfig_yaml = {
            "apiVersion": "v1",
            "clusters": [
                {
                    "cluster": {
                        "certificate-authority-data": f"{test_id}",
                        "server": f"https://0.0.0.0:{test_id}",
                    },
                    "name": f"{context}-cluster",
                }
            ],
            "contexts": [
                {
                    "context": {"cluster": f"{context}-cluster", "user": f"{username}"},
                    "name": f"{context}",
                }
            ],
            "current-context": f"{context}",
            "kind": "Config",
            "preferences": {},
            "users": [{"name": f"{username}", "user": {"token": f"{token}"}}],
        }

        kubeconfig_yaml_str = yaml.dump(kubeconfig_yaml, sort_keys=False)

        cmd_set_label = f"kubectl --kubeconfig {kubeconfig}  --namespace {namespace}  --context {context} label {resource_type} {resource_name} {label} -o yaml "
        output_set_label_yaml = {}
        output_set_label = "0".encode("utf-8")
        values = {
            cmd_set_label: output_set_label,
        }

        mock_yaml_safe_load.side_effect = [kubeconfig_yaml, output_set_label_yaml]

        with patch("builtins.open", mock_open(read_data=kubeconfig_yaml_str)):
            k = KubeInterface(kube_config_file=kubeconfig)
            k.set_label(resource_type, resource_name, label, namespace)

        mock_subprocess.assert_any_call(cmd_set_label, shell=True, stderr=None)

    @patch("lightkube.codecs.load_all_yaml")
    @patch("builtins.open")
    @patch("lightkube.Client.create")
    def test_lightkube_create_service_account(
        self,
        mock_lightkube_client_create,
        mock_open,
        mock_lightkube_codecs_load_all_yaml,
    ):
        kubeconfig = self.kubeconfig_file_for_lighkube_unit_tests
        resource_name = str(uuid.uuid4())
        namespace = str(uuid.uuid4())
        label_key = str(uuid.uuid4())
        label_value = str(uuid.uuid4())

        kubeconfig_yaml_str = str(uuid.uuid4())
        mock_created_resource = LightKubeServiceAccount.from_dict(
            {
                "apiVersion": "v1",
                "kind": "ServiceAccount",
                "metadata": {"name": resource_name, "labels": {label_key: label_value}},
                "name": resource_name,
                "namespace": namespace,
            }
        )

        def side_effect(*args, **kwargs):
            # assert kwargs['obj'] == mock_created_resource
            assert kwargs["name"] == resource_name
            assert kwargs["namespace"] == namespace

        mock_lightkube_client_create.return_value = 0
        mock_lightkube_client_create.side_effect = side_effect

        mock_lightkube_codecs_load_all_yaml.return_value = [mock_created_resource]

        with patch("builtins.open", mock_open(read_data=kubeconfig_yaml_str)):
            k = LightKube(kube_config_file=kubeconfig, defaults=defaults)
            k.create(
                KubernetesResourceType.SERVICEACCOUNT,
                resource_name,
                namespace,
            )

        mock_lightkube_client_create.assert_any_call(
            obj=mock_created_resource, name=resource_name, namespace=namespace
        )

    @patch("lightkube.codecs.load_all_yaml")
    @patch("builtins.open")
    @patch("lightkube.Client.create")
    def test_lightkube_create_role(
        self,
        mock_lightkube_client_create,
        mock_open,
        mock_lightkube_codecs_load_all_yaml,
    ):
        kubeconfig = self.kubeconfig_file_for_lighkube_unit_tests
        resource_name = str(uuid.uuid4())
        namespace = str(uuid.uuid4())
        label_key = str(uuid.uuid4())
        label_value = str(uuid.uuid4())

        kubeconfig_yaml_str = str(uuid.uuid4())
        mock_created_resource = Role.from_dict(
            {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "Role",
                "metadata": {"name": resource_name, "labels": {label_key: label_value}},
                "name": resource_name,
                "namespace": namespace,
            }
        )

        def side_effect(*args, **kwargs):
            # assert kwargs['obj'] == mock_created_resource
            assert kwargs["name"] == resource_name
            assert kwargs["namespace"] == namespace

        mock_lightkube_client_create.return_value = 0
        mock_lightkube_client_create.side_effect = side_effect

        mock_lightkube_codecs_load_all_yaml.return_value = [mock_created_resource]

        with patch("builtins.open", mock_open(read_data=kubeconfig_yaml_str)):
            k = LightKube(kube_config_file=kubeconfig, defaults=defaults)
            k.create(
                KubernetesResourceType.ROLE,
                resource_name,
                namespace,
            )

        mock_lightkube_client_create.assert_any_call(
            obj=mock_created_resource, name=resource_name, namespace=namespace
        )

    @patch("lightkube.codecs.load_all_yaml")
    @patch("builtins.open")
    @patch("lightkube.Client.create")
    def test_lightkube_create_rolebinding(
        self,
        mock_lightkube_client_create,
        mock_open,
        mock_lightkube_codecs_load_all_yaml,
    ):
        kubeconfig = self.kubeconfig_file_for_lighkube_unit_tests
        resource_name = str(uuid.uuid4())
        namespace = str(uuid.uuid4())
        label_key = str(uuid.uuid4())
        label_value = str(uuid.uuid4())

        kubeconfig_yaml_str = str(uuid.uuid4())
        mock_created_resource = RoleBinding.from_dict(
            {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "RoleBinding",
                "metadata": {"name": resource_name, "labels": {label_key: label_value}},
                "name": resource_name,
                "roleRef": resource_name,
                "namespace": namespace,
            }
        )

        def side_effect(*args, **kwargs):
            # assert kwargs['obj'] == mock_created_resource
            assert kwargs["name"] == resource_name
            assert kwargs["namespace"] == namespace

        mock_lightkube_client_create.return_value = 0
        mock_lightkube_client_create.side_effect = side_effect

        mock_lightkube_codecs_load_all_yaml.return_value = [mock_created_resource]

        with patch("builtins.open", mock_open(read_data=kubeconfig_yaml_str)):
            k = LightKube(kube_config_file=kubeconfig, defaults=defaults)
            k.create(
                KubernetesResourceType.ROLEBINDING,
                resource_name,
                namespace,
            )

        mock_lightkube_client_create.assert_any_call(
            obj=mock_created_resource, name=resource_name, namespace=namespace
        )

    @patch("lightkube.codecs.load_all_yaml")
    @patch("builtins.open")
    @patch("lightkube.Client.create")
    def test_lightkube_create_secret(
        self,
        mock_lightkube_client_create,
        mock_open,
        mock_lightkube_codecs_load_all_yaml,
    ):
        kubeconfig = self.kubeconfig_file_for_lighkube_unit_tests
        resource_name = str(uuid.uuid4())
        namespace = str(uuid.uuid4())
        label_key = str(uuid.uuid4())
        label_value = str(uuid.uuid4())
        label = f"{label_key}={label_value}"
        kubeconfig_yaml_str = label
        mock_created_resource = Secret.from_dict(
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {"name": resource_name, "namespace": namespace},
                # "stringData": { label_key : base64.b64encode(label_value.encode("ascii")) },
                "stringData": {},
            }
        )

        def side_effect(*args, **kwargs):
            # assert kwargs['obj'] == mock_created_resource
            assert kwargs["name"] == resource_name
            assert kwargs["namespace"] == namespace

        mock_lightkube_client_create.return_value = 0
        mock_lightkube_client_create.side_effect = side_effect

        mock_lightkube_codecs_load_all_yaml.return_value = mock_created_resource

        with patch("builtins.open", mock_open(read_data=kubeconfig_yaml_str)):
            k = LightKube(kube_config_file=kubeconfig, defaults=defaults)
            k.create(
                KubernetesResourceType.SECRET_GENERIC,
                resource_name,
                namespace,
                **{"from-env-file": "dummy"},
            )
        # for write_call in mock_lightkube_client_create.call_args_list:
        #     print('args: {}'.format(write_call[0]))
        #     print('kwargs: {}'.format(write_call[1]))

        mock_lightkube_client_create.assert_any_call(
            obj=mock_created_resource, name=resource_name, namespace=namespace
        )

    @patch("lightkube.Client.delete")
    def test_lightkube_delete_secret(self, mock_lightkube_client_delete):
        kubeconfig = self.kubeconfig_file_for_lighkube_unit_tests
        resource_name = str(uuid.uuid4())
        namespace = str(uuid.uuid4())

        mock_lightkube_client_delete.return_value = 0

        k = LightKube(kube_config_file=kubeconfig, defaults=defaults)
        k.delete("secret", resource_name, namespace)

        mock_lightkube_client_delete.assert_any_call(
            res=Secret, name=resource_name, namespace=namespace
        )

    @patch("lightkube.Client.delete")
    def test_lightkube_delete_service_account(self, mock_lightkube_client_delete):
        kubeconfig = self.kubeconfig_file_for_lighkube_unit_tests
        resource_name = str(uuid.uuid4())
        namespace = str(uuid.uuid4())

        mock_lightkube_client_delete.return_value = 0

        k = LightKube(kube_config_file=kubeconfig, defaults=defaults)
        k.delete("serviceaccount", resource_name, namespace)

        mock_lightkube_client_delete.assert_any_call(
            res=LightKubeServiceAccount, name=resource_name, namespace=namespace
        )

    @patch("lightkube.Client.delete")
    def test_lightkube_delete_role(self, mock_lightkube_client_delete):
        kubeconfig = self.kubeconfig_file_for_lighkube_unit_tests
        resource_name = str(uuid.uuid4())
        namespace = str(uuid.uuid4())

        mock_lightkube_client_delete.return_value = 0

        k = LightKube(kube_config_file=kubeconfig.strip(), defaults=defaults)
        k.delete("role", resource_name, namespace)

        mock_lightkube_client_delete.assert_any_call(
            res=Role, name=resource_name, namespace=namespace
        )

    @patch("lightkube.Client.delete")
    def test_lightkube_delete_role_binding(self, mock_lightkube_client_delete):
        kubeconfig = self.kubeconfig_file_for_lighkube_unit_tests
        resource_name = str(uuid.uuid4())
        namespace = str(uuid.uuid4())

        mock_lightkube_client_delete.return_value = 0

        k = LightKube(kube_config_file=kubeconfig, defaults=defaults)
        k.delete("rolebinding", resource_name, namespace)

        mock_lightkube_client_delete.assert_any_call(
            res=RoleBinding, name=resource_name, namespace=namespace
        )

    @patch("yaml.safe_load")
    @patch("builtins.open")
    @patch("subprocess.check_output")
    def test_kube_interface_create(
        self, mock_subprocess, mock_open, mock_yaml_safe_load
    ):
        # mock logic
        def side_effect(*args, **kwargs):
            return values[args[0]]

        mock_subprocess.side_effect = side_effect

        test_id = str(uuid.uuid4())
        kubeconfig = str(uuid.uuid4())
        username = str(uuid.uuid4())
        namespace = str(uuid.uuid4())
        context = str(uuid.uuid4())
        token = str(uuid.uuid4())
        resource_type = str(uuid.uuid4())
        resource_name = str(uuid.uuid4())

        kubeconfig_yaml = {
            "apiVersion": "v1",
            "clusters": [
                {
                    "cluster": {
                        "certificate-authority-data": f"{test_id}",
                        "server": f"https://0.0.0.0:{test_id}",
                    },
                    "name": f"{context}-cluster",
                }
            ],
            "contexts": [
                {
                    "context": {"cluster": f"{context}-cluster", "user": f"{username}"},
                    "name": f"{context}",
                }
            ],
            "current-context": f"{context}",
            "kind": "Config",
            "preferences": {},
            "users": [{"name": f"{username}", "user": {"token": f"{token}"}}],
        }

        kubeconfig_yaml_str = yaml.dump(kubeconfig_yaml, sort_keys=False)

        cmd_create = f"kubectl --kubeconfig {kubeconfig}  --namespace {namespace}  --context {context} create {resource_type} {resource_name} --k1=v1 --k2=v21 --k2=v22 -o name "
        output_create_yaml = {}
        output_create = "0".encode("utf-8")
        values = {
            cmd_create: output_create,
        }

        mock_yaml_safe_load.side_effect = [kubeconfig_yaml, output_create_yaml]

        with patch("builtins.open", mock_open(read_data=kubeconfig_yaml_str)):
            k = KubeInterface(kube_config_file=kubeconfig)
            k.create(
                resource_type,
                resource_name,
                namespace,
                **{"k1": "v1", "k2": ["v21", "v22"]},
            )

        mock_subprocess.assert_any_call(cmd_create, shell=True, stderr=None)

    @patch("yaml.safe_load")
    @patch("builtins.open")
    @patch("subprocess.check_output")
    def test_kube_interface_delete(
        self, mock_subprocess, mock_open, mock_yaml_safe_load
    ):
        # mock logic
        def side_effect(*args, **kwargs):
            return values[args[0]]

        mock_subprocess.side_effect = side_effect

        test_id = str(uuid.uuid4())
        kubeconfig = str(uuid.uuid4())
        username = str(uuid.uuid4())
        namespace = str(uuid.uuid4())
        context = str(uuid.uuid4())
        token = str(uuid.uuid4())
        resource_type = str(uuid.uuid4())
        resource_name = str(uuid.uuid4())

        kubeconfig_yaml = {
            "apiVersion": "v1",
            "clusters": [
                {
                    "cluster": {
                        "certificate-authority-data": f"{test_id}",
                        "server": f"https://0.0.0.0:{test_id}",
                    },
                    "name": f"{context}-cluster",
                }
            ],
            "contexts": [
                {
                    "context": {"cluster": f"{context}-cluster", "user": f"{username}"},
                    "name": f"{context}",
                }
            ],
            "current-context": f"{context}",
            "kind": "Config",
            "preferences": {},
            "users": [{"name": f"{username}", "user": {"token": f"{token}"}}],
        }

        kubeconfig_yaml_str = yaml.dump(kubeconfig_yaml, sort_keys=False)

        cmd_delete = f"kubectl --kubeconfig {kubeconfig}  --namespace {namespace}  --context {context} delete {resource_type} {resource_name} --ignore-not-found -o name "
        output_delete_yaml = {}
        output_delete = "0".encode("utf-8")
        values = {
            cmd_delete: output_delete,
        }

        mock_yaml_safe_load.side_effect = [kubeconfig_yaml, output_delete_yaml]

        with patch("builtins.open", mock_open(read_data=kubeconfig_yaml_str)):
            k = KubeInterface(kube_config_file=kubeconfig)
            k.delete(resource_type, resource_name, namespace)

        mock_subprocess.assert_any_call(cmd_delete, shell=True, stderr=None)

    @patch("lightkube.codecs.dump_all_yaml")
    @patch("lightkube.Client.list")
    def test_lightkube_get_service_accounts(
        self, mock_lightkube_client_list, mock_lightkube_codecs_dump_all_yaml
    ):
        kubeconfig = self.kubeconfig_file_for_lighkube_unit_tests
        resource_name = str(uuid.uuid4())
        namespace = str(uuid.uuid4())
        label_key = str(uuid.uuid4())
        label_value = str(uuid.uuid4())
        label = f"{label_key}={label_value}"
        mock_service_account = LightKubeServiceAccount.from_dict(
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {"name": resource_name, "namespace": namespace},
                "name": resource_name,
            }
        )

        def side_effect(*args, **kwargs):
            assert list(args[0]).__getitem__(0) == mock_service_account

        mock_lightkube_client_list.return_value = [mock_service_account]
        mock_lightkube_codecs_dump_all_yaml.side_effect = side_effect

        k = LightKube(kube_config_file=kubeconfig, defaults=defaults)
        k.get_service_accounts(labels=[label])

    @patch("lightkube.codecs.dump_all_yaml")
    @patch("lightkube.Client.get")
    def test_lightkube_get_service_account(
        self, mock_lightkube_client_get, mock_lightkube_codecs_dump_all_yaml
    ):
        kubeconfig = self.kubeconfig_file_for_lighkube_unit_tests
        resource_name = str(uuid.uuid4())
        namespace = str(uuid.uuid4())
        mock_service_account = LightKubeServiceAccount.from_dict(
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {"name": resource_name, "namespace": namespace},
                "name": resource_name,
            }
        )

        def side_effect(*args, **kwargs):
            assert args[0] == [mock_service_account]

        mock_lightkube_client_get.return_value = mock_service_account
        mock_lightkube_codecs_dump_all_yaml.side_effect = side_effect

        k = LightKube(kube_config_file=kubeconfig, defaults=defaults)
        k.get_service_account(resource_name)

    @patch("yaml.safe_load")
    @patch("builtins.open")
    @patch("subprocess.check_output")
    def test_kube_interface_get_service_accounts(
        self, mock_subprocess, mock_open, mock_yaml_safe_load
    ):
        test_id = str(uuid.uuid4())
        kubeconfig = str(uuid.uuid4())
        username = str(uuid.uuid4())
        namespace = str(uuid.uuid4())
        context = str(uuid.uuid4())
        token = str(uuid.uuid4())
        label1 = str(uuid.uuid4())
        label2 = str(uuid.uuid4())
        labels = [label1, label2]

        kubeconfig_yaml = {
            "apiVersion": "v1",
            "clusters": [
                {
                    "cluster": {
                        "certificate-authority-data": f"{test_id}",
                        "server": f"https://0.0.0.0:{test_id}",
                    },
                    "name": f"{context}-cluster",
                }
            ],
            "contexts": [
                {
                    "context": {"cluster": f"{context}-cluster", "user": f"{username}"},
                    "name": f"{context}",
                }
            ],
            "current-context": f"{context}",
            "kind": "Config",
            "preferences": {},
            "users": [{"name": f"{username}", "user": {"token": f"{token}"}}],
        }

        kubeconfig_yaml_str = yaml.dump(kubeconfig_yaml, sort_keys=False)

        cmd_get_sa = f"kubectl --kubeconfig {kubeconfig}  --context {context} get serviceaccount -l {label1}  -l {label2} -n {namespace} -o yaml "
        output_get_sa_yaml = {
            "apiVersion": "v1",
            "items": [
                {
                    "apiVersion": "v1",
                    "kind": "ServiceAccount",
                    "metadata": {
                        "creationTimestamp": "2022-11-21T14:32:06Z",
                        "labels": {
                            MANAGED_BY_LABELNAME: SPARK8S_LABEL,
                            PRIMARY_LABELNAME: "1",
                        },
                        "name": f"{username}",
                        "namespace": f"{namespace}",
                        "resourceVersion": "321848",
                        "uid": "87ef7231-8106-4a36-b545-d8cf167788a6",
                    },
                }
            ],
            "kind": "List",
            "metadata": {"resourceVersion": ""},
        }
        output_get_sa = yaml.dump(output_get_sa_yaml, sort_keys=False).encode("utf-8")

        # mock logic
        def side_effect(*args, **kwargs):
            return output_get_sa

        mock_subprocess.side_effect = side_effect

        mock_yaml_safe_load.side_effect = [kubeconfig_yaml, output_get_sa_yaml]

        with patch("builtins.open", mock_open(read_data=kubeconfig_yaml_str)):
            k = KubeInterface(kube_config_file=kubeconfig)
            sa_list = k.get_service_accounts(namespace, labels)
            self.assertEqual(sa_list[0].get("metadata").get("name"), username)
            self.assertEqual(sa_list[0].get("metadata").get("namespace"), namespace)

        mock_subprocess.assert_any_call(cmd_get_sa, shell=True, stderr=None)

    @patch("yaml.safe_load")
    @patch("builtins.open")
    @patch("subprocess.check_output")
    def test_kube_interface_autodetect(
        self, mock_subprocess, mock_open, mock_yaml_safe_load
    ):
        test_id = str(uuid.uuid4())
        kubeconfig = str(uuid.uuid4())
        username = str(uuid.uuid4())
        namespace = str(uuid.uuid4())
        context = str(uuid.uuid4())
        token = str(uuid.uuid4())
        kubectl_cmd_str = str(uuid.uuid4())

        kubeconfig_yaml = {
            "apiVersion": "v1",
            "clusters": [
                {
                    "cluster": {
                        "certificate-authority-data": f"{test_id}",
                        "server": f"https://0.0.0.0:{test_id}",
                    },
                    "name": f"{context}-cluster",
                }
            ],
            "contexts": [
                {
                    "context": {"cluster": f"{context}-cluster", "user": f"{username}"},
                    "name": f"{context}",
                }
            ],
            "current-context": f"{context}",
            "kind": "Config",
            "preferences": {},
            "users": [{"name": f"{username}", "user": {"token": f"{token}"}}],
        }

        kubeconfig_yaml_str = yaml.dump(kubeconfig_yaml, sort_keys=False)

        cmd_autodetect = (
            f"{kubectl_cmd_str} --context {context} config view --minify -o yaml"
        )
        output_autodetect_yaml = {
            "apiVersion": "v1",
            "items": [
                {
                    "apiVersion": "v1",
                    "kind": "ServiceAccount",
                    "metadata": {
                        "creationTimestamp": "2022-11-21T14:32:06Z",
                        "labels": {
                            MANAGED_BY_LABELNAME: SPARK8S_LABEL,
                            PRIMARY_LABELNAME: "1",
                        },
                        "name": f"{username}",
                        "namespace": f"{namespace}",
                        "resourceVersion": "321848",
                        "uid": "87ef7231-8106-4a36-b545-d8cf167788a6",
                    },
                }
            ],
            "kind": "List",
            "metadata": {"resourceVersion": ""},
        }
        output_autodetect = yaml.dump(output_autodetect_yaml, sort_keys=False).encode(
            "utf-8"
        )

        # mock logic
        def side_effect(*args, **kwargs):
            return output_autodetect

        mock_subprocess.side_effect = side_effect
        mock_yaml_safe_load.side_effect = [kubeconfig_yaml, output_autodetect_yaml]

        with patch("builtins.open", mock_open(read_data=kubeconfig_yaml_str)):
            k = KubeInterface(kube_config_file=kubeconfig)
            ki = k.autodetect(context, kubectl_cmd_str)
            self.assertEqual(ki.context_name, context)
            self.assertEqual(ki.kubectl_cmd, kubectl_cmd_str)

        mock_subprocess.assert_any_call(cmd_autodetect, shell=True, stderr=None)

    @patch("yaml.safe_load")
    @patch("builtins.open")
    @patch("subprocess.check_output")
    def test_kube_interface_select_by_master(
        self, mock_subprocess, mock_open, mock_yaml_safe_load
    ):
        test_id = str(uuid.uuid4())
        kubeconfig = str(uuid.uuid4())
        username = str(uuid.uuid4())
        namespace = str(uuid.uuid4())
        context = str(uuid.uuid4())
        token = str(uuid.uuid4())

        kubeconfig_yaml = {
            "apiVersion": "v1",
            "clusters": [
                {
                    "cluster": {
                        "certificate-authority-data": f"{test_id}",
                        "server": f"https://0.0.0.0:{test_id}",
                    },
                    "name": f"{context}-cluster",
                }
            ],
            "contexts": [
                {
                    "context": {"cluster": f"{context}-cluster", "user": f"{username}"},
                    "name": f"{context}",
                }
            ],
            "current-context": f"{context}",
            "kind": "Config",
            "preferences": {},
            "users": [{"name": f"{username}", "user": {"token": f"{token}"}}],
        }

        kubeconfig_yaml_str = yaml.dump(kubeconfig_yaml, sort_keys=False)

        output_select_by_master_yaml = {
            "apiVersion": "v1",
            "items": [
                {
                    "apiVersion": "v1",
                    "kind": "ServiceAccount",
                    "metadata": {
                        "creationTimestamp": "2022-11-21T14:32:06Z",
                        "labels": {
                            MANAGED_BY_LABELNAME: SPARK8S_LABEL,
                            PRIMARY_LABELNAME: "1",
                        },
                        "name": f"{username}",
                        "namespace": f"{namespace}",
                        "resourceVersion": "321848",
                        "uid": "87ef7231-8106-4a36-b545-d8cf167788a6",
                    },
                }
            ],
            "kind": "List",
            "metadata": {"resourceVersion": ""},
        }

        mock_yaml_safe_load.side_effect = [
            kubeconfig_yaml,
            output_select_by_master_yaml,
        ]

        with patch("builtins.open", mock_open(read_data=kubeconfig_yaml_str)):
            k = KubeInterface(kube_config_file=kubeconfig)
            self.assertEqual(k, k.select_by_master(f"https://0.0.0.0:{test_id}"))

    @patch("spark8t.services.KubeInterface")
    def test_k8s_registry_retrieve_account_configurations(self, mock_kube_interface):
        data = {"k": "v"}
        mock_kube_interface.get_secret.return_value = {"data": data}
        registry = K8sServiceAccountRegistry(mock_kube_interface)
        self.assertEqual(
            registry._retrieve_account_configurations(
                str(uuid.uuid4()), str(uuid.uuid4())
            ).props,
            data,
        )

    @patch("spark8t.services.KubeInterface")
    def test_k8s_registry_all(self, mock_kube_interface):
        data = {"k": "v"}
        mock_kube_interface.get_secret.return_value = {"data": data}

        name1 = str(uuid.uuid4())
        namespace1 = str(uuid.uuid4())
        labels11 = PRIMARY_LABELNAME
        labels12 = str(uuid.uuid4())
        name2 = str(uuid.uuid4())
        namespace2 = str(uuid.uuid4())
        labels21 = str(uuid.uuid4())
        labels22 = str(uuid.uuid4())

        sa1 = {
            "metadata": {
                "name": name1,
                "namespace": namespace1,
                "labels": [labels11, labels12],
            }
        }
        sa2 = {
            "metadata": {
                "name": name2,
                "namespace": namespace2,
                "labels": [labels21, labels22],
            }
        }

        mock_kube_interface.get_service_accounts.return_value = [sa1, sa2]
        registry = K8sServiceAccountRegistry(mock_kube_interface)
        output = registry.all()
        self.assertEqual(output[0].name, name1)
        self.assertEqual(output[0].namespace, namespace1)
        self.assertEqual(output[0].primary, True)
        self.assertEqual(output[1].name, name2)
        self.assertEqual(output[1].namespace, namespace2)
        self.assertEqual(output[1].primary, False)

    @patch("spark8t.services.KubeInterface")
    def test_k8s_registry_set_primary(self, mock_kube_interface):
        data = {"k": "v"}
        mock_kube_interface.get_secret.return_value = {"data": data}

        name1 = str(uuid.uuid4())
        namespace1 = str(uuid.uuid4())
        labels11 = PRIMARY_LABELNAME
        labels12 = str(uuid.uuid4())
        name2 = str(uuid.uuid4())
        namespace2 = str(uuid.uuid4())
        labels21 = str(uuid.uuid4())
        labels22 = str(uuid.uuid4())

        sa1 = {
            "metadata": {
                "name": name1,
                "namespace": namespace1,
                "labels": [labels11, labels12],
            }
        }
        sa2 = {
            "metadata": {
                "name": name2,
                "namespace": namespace2,
                "labels": [labels21, labels22],
            }
        }

        mock_kube_interface.get_service_accounts.return_value = [sa1, sa2]
        mock_kube_interface.get_service_account.return_value = sa2
        mock_kube_interface.set_label.return_value = 0
        mock_kube_interface.remove_label.return_value = 0
        registry = K8sServiceAccountRegistry(mock_kube_interface)
        self.assertEqual(
            registry.set_primary(f"{namespace2}:{name2}"), f"{namespace2}:{name2}"
        )

        mock_kube_interface.remove_label.assert_any_call(
            "serviceaccount",
            name1,
            f"{PRIMARY_LABELNAME}",
            namespace1,
        )

        mock_kube_interface.remove_label.assert_any_call(
            "rolebinding",
            f"{name1}-role-binding",
            f"{PRIMARY_LABELNAME}",
            namespace1,
        )

        mock_kube_interface.set_label.assert_any_call(
            "serviceaccount",
            name2,
            f"{PRIMARY_LABELNAME}=True",
            namespace2,
        )

        mock_kube_interface.set_label.assert_any_call(
            "rolebinding",
            f"{name2}-role-binding",
            f"{PRIMARY_LABELNAME}=True",
            namespace2,
        )

    @patch("spark8t.services.KubeInterface")
    def test_k8s_registry_create(self, mock_kube_interface):
        data = {"k": "v"}
        mock_kube_interface.get_secret.return_value = {"data": data}

        name1 = str(uuid.uuid4())
        namespace1 = str(uuid.uuid4())
        labels11 = PRIMARY_LABELNAME
        labels12 = str(uuid.uuid4())
        name2 = str(uuid.uuid4())
        namespace2 = str(uuid.uuid4())
        labels21 = str(uuid.uuid4())
        labels22 = str(uuid.uuid4())
        name3 = str(uuid.uuid4())
        namespace3 = str(uuid.uuid4())
        labels31 = PRIMARY_LABELNAME
        labels32 = str(uuid.uuid4())
        api_server = str(uuid.uuid4())

        sa1 = {
            "metadata": {
                "name": name1,
                "namespace": namespace1,
                "labels": [labels11, labels12],
            }
        }
        sa2 = {
            "metadata": {
                "name": name2,
                "namespace": namespace2,
                "labels": [labels21, labels22],
            }
        }
        sa3 = {
            "metadata": {
                "name": name3,
                "namespace": namespace3,
                "labels": [labels31, labels32],
            }
        }
        sa3_obj = ServiceAccount(
            name=name3,
            namespace=namespace3,
            api_server=api_server,
            primary=True,
            extra_confs=PropertyFile(data),
        )

        mock_kube_interface.get_service_accounts.return_value = [sa1, sa2, sa3]
        mock_kube_interface.get_service_account.return_value = sa3
        mock_kube_interface.set_label.return_value = 0
        mock_kube_interface.remove_label.return_value = 0
        mock_kube_interface.create.return_value = 0

        registry = K8sServiceAccountRegistry(mock_kube_interface)
        self.assertEqual(registry.create(sa3_obj), sa3_obj.id)

        for call in mock_kube_interface.create.call_args_list:
            print(call)

        mock_kube_interface.create.assert_any_call(
            KubernetesResourceType.SERVICEACCOUNT,
            name3,
            namespace=namespace3,
            username=name3,
        )

        mock_kube_interface.create.assert_any_call(
            "role",
            f"{name3}-role",
            namespace=namespace3,
            **{
                "resource": ["pods", "configmaps", "services"],
                "verb": ["create", "get", "list", "watch", "delete"],
            },
        )

        mock_kube_interface.create.assert_any_call(
            KubernetesResourceType.ROLEBINDING,
            f"{name3}-role-binding",
            namespace=namespace3,
            **{
                "role": f"{name3}-role",
                "serviceaccount": sa3_obj.id,
                "username": name3,
            },
        )

        mock_kube_interface.set_label.assert_any_call(
            KubernetesResourceType.SERVICEACCOUNT,
            name3,
            f"{MANAGED_BY_LABELNAME}={SPARK8S_LABEL}",
            namespace=namespace3,
        )

        mock_kube_interface.set_label.assert_any_call(
            KubernetesResourceType.ROLEBINDING,
            f"{name3}-role-binding",
            f"{MANAGED_BY_LABELNAME}={SPARK8S_LABEL}",
            namespace=namespace3,
        )

        mock_kube_interface.remove_label.assert_any_call(
            KubernetesResourceType.SERVICEACCOUNT,
            name1,
            f"{PRIMARY_LABELNAME}",
            namespace1,
        )

        mock_kube_interface.remove_label.assert_any_call(
            KubernetesResourceType.ROLEBINDING,
            f"{name1}-role-binding",
            f"{PRIMARY_LABELNAME}",
            namespace1,
        )

        mock_kube_interface.set_label.assert_any_call(
            KubernetesResourceType.SERVICEACCOUNT,
            name3,
            f"{PRIMARY_LABELNAME}=True",
            namespace3,
        )

        mock_kube_interface.set_label.assert_any_call(
            KubernetesResourceType.ROLEBINDING,
            f"{name3}-role-binding",
            f"{PRIMARY_LABELNAME}=True",
            namespace3,
        )

    @patch("spark8t.services.KubeInterface")
    def test_k8s_registry_delete(self, mock_kube_interface):
        data = {"k": "v"}
        mock_kube_interface.get_secret.return_value = {"data": data}

        name2 = str(uuid.uuid4())
        namespace2 = str(uuid.uuid4())

        mock_kube_interface.delete.return_value = 0

        registry = K8sServiceAccountRegistry(mock_kube_interface)

        self.assertEqual(
            registry.delete(f"{namespace2}:{name2}"), f"{namespace2}:{name2}"
        )
        mock_kube_interface.delete.assert_any_call(
            KubernetesResourceType.SERVICEACCOUNT, name2, namespace=namespace2
        )
        mock_kube_interface.delete.assert_any_call(
            KubernetesResourceType.ROLE, f"{name2}-role", namespace=namespace2
        )
        mock_kube_interface.delete.assert_any_call(
            KubernetesResourceType.ROLEBINDING,
            f"{name2}-role-binding",
            namespace=namespace2,
        )

        mock_kube_interface.delete.assert_any_call(
            KubernetesResourceType.SECRET,
            f"{SPARK8S_LABEL}-sa-conf-{name2}",
            namespace=namespace2,
        )


if __name__ == "__main__":
    logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level="DEBUG")
    unittest.main()
