import base64
import io
import os
import uuid
from typing import Generator
from unittest.mock import patch

import pytest
import yaml
from lightkube.resources.core_v1 import Secret
from lightkube.resources.core_v1 import ServiceAccount as LightKubeServiceAccount
from lightkube.resources.rbac_authorization_v1 import Role, RoleBinding
from lightkube.types import PatchType
from OpenSSL import crypto

from spark8t.cli import defaults
from spark8t.domain import KubernetesResourceType, ServiceAccount
from spark8t.kube_interface.lightkube import LightKubeInterface
from spark8t.literals import (
    GENERATED_BY_LABELNAME,
    MANAGED_BY_LABELNAME,
    PRIMARY_LABELNAME,
    SPARK8S_LABEL,
)
from spark8t.registry.k8s import K8sServiceAccountRegistry
from spark8t.utils import PropertyFile

####################################################################################################
# Helpers
####################################################################################################


TMP_KUBECONF = "./lightkube_unittest_kubeconfig.yaml"


def generate_kube_config_file(kube_config_file_name: str) -> str:
    username1 = "username1"
    username2 = "username2"
    username3 = "username3"
    context1 = "context1"
    context2 = "context2"
    context3 = "context3"

    token1 = str(uuid.uuid4())
    token2 = str(uuid.uuid4())
    token3 = str(uuid.uuid4())
    ca_cert_data = cert_gen()

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

    filename = f"{kube_config_file_name}-{uuid.uuid4()}"
    with open(filename, "w") as file:
        yaml.dump(kubeconfig_yaml, file)
    return filename


@pytest.fixture
def tmp_kubeconf() -> Generator[str, None, None]:
    filename = generate_kube_config_file(TMP_KUBECONF)
    yield filename
    os.remove(filename)


def cert_gen(
    emailAddress: str = "emailAddress",
    commonName: str = "commonName",
    countryName: str = "NT",
    localityName: str = "localityName",
    stateOrProvinceName: str = "stateOrProvinceName",
    organizationName: str = "organizationName",
    organizationUnitName: str = "organizationUnitName",
    serialNumber: int = 0,
    validityStartInSeconds: int = 0,
    validityEndInSeconds: int = 10 * 365 * 24 * 60 * 60,
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
        buffer.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
        buffer.seek(0)
        return base64.b64encode(buffer.read().encode("ascii")).decode("ascii")

    # with open(CERT_FILE, "wt") as f:
    #     f.write()
    # with open(KEY_FILE, "wt") as f:
    #     f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))


####################################################################################################
# Tests
####################################################################################################


def test_conf_expansion_cli() -> None:
    home_var = "/this/is/my/home"

    parsed_property = PropertyFile.parse_conf_overrides(
        ["my-conf=$HOME/folder", "my-other-conf=/this/does/$NOT/change"],
        environ_vars={"HOME": home_var},
    )
    assert parsed_property.props["my-conf"] == f"{home_var}/folder"
    assert parsed_property.props["my-other-conf"] == "/this/does/$NOT/change"


def test_lightkube(tmp_kubeconf: str) -> None:
    # mock logic
    context1 = "context1"
    username2 = "username2"
    context2 = "context2"
    context3 = "context3"

    k = LightKubeInterface(
        kube_config_file=tmp_kubeconf,
        defaults=defaults,
    )

    assert k.context_name == context2
    assert k.with_context(context3).context_name == context3
    assert (single_config := k.with_context(context3).single_config) is not None
    assert single_config.context.cluster == f"{context3}-cluster"

    assert context1 in k.kube_config.contexts
    assert context2 in k.kube_config.contexts
    assert context3 in k.kube_config.contexts
    assert len(k.kube_config.contexts) == 3

    assert (current_config := k.single_config) is not None
    current_context = current_config.context
    assert current_context.cluster == f"{context2}-cluster"
    assert current_context.user == f"{username2}"

    current_cluster = current_config.cluster
    assert current_cluster.server == "https://0.0.0.1:9090"


def test_lightkube_get_secret(mocker, tmp_kubeconf: str) -> None:
    mock_lightkube_client_get = mocker.patch("lightkube.Client.get")
    kubeconfig = tmp_kubeconf
    secret_name = str(uuid.uuid4())
    namespace = str(uuid.uuid4())
    conf_key = str(uuid.uuid4())
    conf_value = str(uuid.uuid4())

    def side_effect(*args, **kwargs) -> Secret:
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

    k = LightKubeInterface(kube_config_file=kubeconfig, defaults=defaults)
    secret_result = k.get_secret(secret_name, namespace)
    assert conf_value == secret_result["data"][conf_key]


def test_lightkube_set_label_service_account(mocker, tmp_kubeconf: str) -> None:
    mock_lightkube_client_patch = mocker.patch("lightkube.Client.patch")
    kubeconfig = tmp_kubeconf
    resource_name = str(uuid.uuid4())
    namespace = str(uuid.uuid4())
    label_key = str(uuid.uuid4())
    label_value = str(uuid.uuid4())
    label = f"{label_key}={label_value}"

    mock_lightkube_client_patch.return_value = 0

    k = LightKubeInterface(kube_config_file=kubeconfig, defaults=defaults)
    k.set_label(KubernetesResourceType.SERVICEACCOUNT, resource_name, label, namespace)

    patch = {"metadata": {"labels": {label_key: label_value}}}

    mock_lightkube_client_patch.assert_any_call(
        res=LightKubeServiceAccount,
        name=resource_name,
        namespace=namespace,
        obj=patch,
        force=True,
    )


def test_lightkube_set_label_role(mocker, tmp_kubeconf: str) -> None:
    mock_lightkube_client_patch = mocker.patch("lightkube.Client.patch")
    kubeconfig = tmp_kubeconf
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

    k = LightKubeInterface(kube_config_file=kubeconfig, defaults=defaults)
    k.set_label(KubernetesResourceType.ROLE, resource_name, label, namespace)


def test_lightkube_set_label_role_binding(mocker, tmp_kubeconf: str) -> None:
    mock_lightkube_client_patch = mocker.patch("lightkube.Client.patch")
    kubeconfig = tmp_kubeconf
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

    k = LightKubeInterface(kube_config_file=kubeconfig, defaults=defaults)
    k.set_label(KubernetesResourceType.ROLEBINDING, resource_name, label, namespace)


def test_lightkube_remove_label_service_account(mocker, tmp_kubeconf: str) -> None:
    mock_lightkube_client_patch = mocker.patch("lightkube.Client.patch")
    kubeconfig = tmp_kubeconf
    resource_name = str(uuid.uuid4())
    namespace = str(uuid.uuid4())
    label_key = str(uuid.uuid4())

    mock_lightkube_client_patch.return_value = 0

    k = LightKubeInterface(kube_config_file=kubeconfig, defaults=defaults)
    k.remove_label(
        KubernetesResourceType.SERVICEACCOUNT, resource_name, label_key, namespace
    )

    patch = [
        {"op": "remove", "path": f"/metadata/labels/{label_key.replace('/', '~1')}"}
    ]

    mock_lightkube_client_patch.assert_any_call(
        res=LightKubeServiceAccount,
        name=resource_name,
        namespace=namespace,
        obj=patch,
        patch_type=PatchType.JSON,
    )


def test_lightkube_remove_label_role(mocker, tmp_kubeconf: str) -> None:
    mock_lightkube_client_patch = mocker.patch("lightkube.Client.patch")
    kubeconfig = tmp_kubeconf
    resource_name = str(uuid.uuid4())
    namespace = str(uuid.uuid4())
    label_key = str(uuid.uuid4())

    mock_lightkube_client_patch.return_value = 0

    k = LightKubeInterface(kube_config_file=kubeconfig, defaults=defaults)
    k.remove_label(KubernetesResourceType.ROLE, resource_name, label_key, namespace)

    patch = [
        {"op": "remove", "path": f"/metadata/labels/{label_key.replace('/', '~1')}"}
    ]

    mock_lightkube_client_patch.assert_any_call(
        res=Role,
        name=resource_name,
        namespace=namespace,
        obj=patch,
        patch_type=PatchType.JSON,
    )


def test_lightkube_remove_label_role_binding(mocker, tmp_kubeconf: str) -> None:
    mock_lightkube_client_patch = mocker.patch("lightkube.Client.patch")
    kubeconfig = tmp_kubeconf
    resource_name = str(uuid.uuid4())
    namespace = str(uuid.uuid4())
    label_key = str(uuid.uuid4())

    mock_lightkube_client_patch.return_value = 0

    k = LightKubeInterface(kube_config_file=kubeconfig, defaults=defaults)
    k.remove_label(
        KubernetesResourceType.ROLEBINDING, resource_name, label_key, namespace
    )

    patch = [
        {"op": "remove", "path": f"/metadata/labels/{label_key.replace('/', '~1')}"}
    ]

    mock_lightkube_client_patch.assert_any_call(
        res=RoleBinding,
        name=resource_name,
        namespace=namespace,
        obj=patch,
        patch_type=PatchType.JSON,
    )


def test_lightkube_create_service_account(mocker, tmp_kubeconf: str) -> None:
    mock_lightkube_codecs_load_all_yaml = mocker.patch("lightkube.codecs.load_all_yaml")
    mock_open = mocker.patch("builtins.open")
    mock_lightkube_client_create = mocker.patch("lightkube.Client.create")

    kubeconfig = tmp_kubeconf
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

    def side_effect(*args, **kwargs) -> None:
        # assert kwargs['obj'] == mock_created_resource
        assert kwargs["name"] == resource_name
        assert kwargs["namespace"] == namespace

    mock_lightkube_client_create.return_value = 0
    mock_lightkube_client_create.side_effect = side_effect

    mock_lightkube_codecs_load_all_yaml.return_value = [mock_created_resource]

    with patch("builtins.open", mock_open(read_data=kubeconfig_yaml_str)):
        k = LightKubeInterface(kube_config_file=kubeconfig, defaults=defaults)
        k.create(
            KubernetesResourceType.SERVICEACCOUNT,
            resource_name,
            namespace,
        )

    mock_lightkube_client_create.assert_any_call(
        obj=mock_created_resource,
        name=resource_name,
        namespace=namespace,
    )


def test_lightkube_create_role(mocker, tmp_kubeconf: str) -> None:
    mock_lightkube_codecs_load_all_yaml = mocker.patch("lightkube.codecs.load_all_yaml")
    mock_open = mocker.patch("builtins.open")
    mock_lightkube_client_create = mocker.patch("lightkube.Client.create")

    kubeconfig = tmp_kubeconf
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

    def side_effect(*args, **kwargs) -> None:
        # assert kwargs['obj'] == mock_created_resource
        assert kwargs["name"] == resource_name
        assert kwargs["namespace"] == namespace

    mock_lightkube_client_create.return_value = 0
    mock_lightkube_client_create.side_effect = side_effect

    mock_lightkube_codecs_load_all_yaml.return_value = [mock_created_resource]

    with patch("builtins.open", mock_open(read_data=kubeconfig_yaml_str)):
        k = LightKubeInterface(kube_config_file=kubeconfig, defaults=defaults)
        k.create(
            KubernetesResourceType.ROLE,
            resource_name,
            namespace,
        )

    mock_lightkube_client_create.assert_any_call(
        obj=mock_created_resource,
        name=resource_name,
        namespace=namespace,
    )


def test_lightkube_create_rolebinding(mocker, tmp_kubeconf: str) -> None:
    mock_lightkube_codecs_load_all_yaml = mocker.patch("lightkube.codecs.load_all_yaml")
    mock_open = mocker.patch("builtins.open")
    mock_lightkube_client_create = mocker.patch("lightkube.Client.create")

    kubeconfig = tmp_kubeconf
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

    def side_effect(*args, **kwargs) -> None:
        # assert kwargs['obj'] == mock_created_resource
        assert kwargs["name"] == resource_name
        assert kwargs["namespace"] == namespace

    mock_lightkube_client_create.return_value = 0
    mock_lightkube_client_create.side_effect = side_effect

    mock_lightkube_codecs_load_all_yaml.return_value = [mock_created_resource]

    with patch("builtins.open", mock_open(read_data=kubeconfig_yaml_str)):
        k = LightKubeInterface(kube_config_file=kubeconfig, defaults=defaults)
        print(f"rn: {resource_name}, namespace: {namespace}")
        k.create(
            KubernetesResourceType.ROLEBINDING,
            resource_name,
            namespace,
        )

    mock_lightkube_client_create.assert_any_call(
        obj=mock_created_resource,
        name=resource_name,
        namespace=namespace,
    )


def test_lightkube_create_secret(mocker, tmp_kubeconf: str) -> None:
    mock_lightkube_codecs_load_all_yaml = mocker.patch("lightkube.codecs.load_all_yaml")
    mock_open = mocker.patch("builtins.open")
    mock_lightkube_client_create = mocker.patch("lightkube.Client.create")

    kubeconfig = tmp_kubeconf
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
            "metadata": {
                "name": resource_name,
                "namespace": namespace,
                "labels": {GENERATED_BY_LABELNAME: SPARK8S_LABEL},
            },
            "stringData": None,
        }
    )

    def side_effect(*args, **kwargs) -> None:
        # assert kwargs['obj'] == mock_created_resource
        assert kwargs["name"] == resource_name
        assert kwargs["namespace"] == namespace

    mock_lightkube_client_create.return_value = 0
    mock_lightkube_client_create.side_effect = side_effect

    mock_lightkube_codecs_load_all_yaml.return_value = mock_created_resource

    with patch("builtins.open", mock_open(read_data=kubeconfig_yaml_str)):
        k = LightKubeInterface(kube_config_file=kubeconfig, defaults=defaults)
        k.create(
            KubernetesResourceType.SECRET_GENERIC,
            resource_name,
            namespace,
            dry_run=False,
        )

    mock_lightkube_client_create.assert_any_call(
        obj=mock_created_resource,
        name=resource_name,
        namespace=namespace,
    )


def test_lightkube_delete_secret(mocker, tmp_kubeconf: str) -> None:
    mock_lightkube_client_delete = mocker.patch("lightkube.Client.delete")
    kubeconfig = tmp_kubeconf
    resource_name = str(uuid.uuid4())
    namespace = str(uuid.uuid4())

    mock_lightkube_client_delete.return_value = 0

    k = LightKubeInterface(kube_config_file=kubeconfig, defaults=defaults)
    k.delete(KubernetesResourceType.SECRET, resource_name, namespace)

    mock_lightkube_client_delete.assert_any_call(
        res=Secret, name=resource_name, namespace=namespace
    )


def test_lightkube_delete_service_account(mocker, tmp_kubeconf: str) -> None:
    mock_lightkube_client_delete = mocker.patch("lightkube.Client.delete")
    kubeconfig = tmp_kubeconf
    resource_name = str(uuid.uuid4())
    namespace = str(uuid.uuid4())

    mock_lightkube_client_delete.return_value = 0

    k = LightKubeInterface(kube_config_file=kubeconfig, defaults=defaults)
    k.delete(KubernetesResourceType.SERVICEACCOUNT, resource_name, namespace)

    mock_lightkube_client_delete.assert_any_call(
        res=LightKubeServiceAccount, name=resource_name, namespace=namespace
    )


def test_lightkube_delete_role(mocker, tmp_kubeconf: str) -> None:
    mock_lightkube_client_delete = mocker.patch("lightkube.Client.delete")
    kubeconfig = tmp_kubeconf
    resource_name = str(uuid.uuid4())
    namespace = str(uuid.uuid4())

    mock_lightkube_client_delete.return_value = 0

    k = LightKubeInterface(kube_config_file=kubeconfig.strip(), defaults=defaults)
    k.delete(KubernetesResourceType.ROLE, resource_name, namespace)

    mock_lightkube_client_delete.assert_any_call(
        res=Role, name=resource_name, namespace=namespace
    )


def test_lightkube_delete_role_binding(mocker, tmp_kubeconf: str) -> None:
    mock_lightkube_client_delete = mocker.patch("lightkube.Client.delete")
    kubeconfig = tmp_kubeconf
    resource_name = str(uuid.uuid4())
    namespace = str(uuid.uuid4())

    mock_lightkube_client_delete.return_value = 0

    k = LightKubeInterface(kube_config_file=kubeconfig, defaults=defaults)
    k.delete(KubernetesResourceType.ROLEBINDING, resource_name, namespace)

    mock_lightkube_client_delete.assert_any_call(
        res=RoleBinding, name=resource_name, namespace=namespace
    )


def test_lightkube_get_service_accounts(mocker, tmp_kubeconf: str) -> None:
    mock_lightkube_codecs_dump_all_yaml = mocker.patch("lightkube.codecs.dump_all_yaml")
    mock_lightkube_client_list = mocker.patch("lightkube.Client.list")
    kubeconfig = tmp_kubeconf
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

    def side_effect(*args, **kwargs) -> None:
        assert list(args[0]).__getitem__(0) == mock_service_account

    mock_lightkube_client_list.return_value = [mock_service_account]
    mock_lightkube_codecs_dump_all_yaml.side_effect = side_effect

    k = LightKubeInterface(kube_config_file=kubeconfig, defaults=defaults)
    k.get_service_accounts(labels=[label])


def test_lightkube_get_service_account(mocker, tmp_kubeconf: str) -> None:
    mock_lightkube_codecs_dump_all_yaml = mocker.patch("lightkube.codecs.dump_all_yaml")
    mock_lightkube_client_get = mocker.patch("lightkube.Client.get")
    kubeconfig = tmp_kubeconf
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

    def side_effect(*args, **kwargs) -> None:
        assert args[0] == [mock_service_account]

    mock_lightkube_client_get.return_value = mock_service_account
    mock_lightkube_codecs_dump_all_yaml.side_effect = side_effect

    k = LightKubeInterface(kube_config_file=kubeconfig, defaults=defaults)
    k.get_service_account(resource_name)


def test_k8s_registry_secret_account_configurations(mocker) -> None:
    mock_kube_interface = mocker.patch(
        "spark8t.kube_interface.lightkube.LightKubeInterface"
    )
    data = {"k": "v"}
    mock_kube_interface.get_secret.return_value = {"data": data}
    registry = K8sServiceAccountRegistry(mock_kube_interface)
    assert (
        registry._retrieve_secret_configurations(
            str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
        ).props
        == data
    )


def test_k8s_registry_all(mocker) -> None:
    mock_kube_interface = mocker.patch(
        "spark8t.kube_interface.lightkube.LightKubeInterface"
    )
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
    assert output[0].name == name1
    assert output[0].namespace == namespace1
    assert output[0].primary is True
    assert output[1].name == name2
    assert output[1].namespace == namespace2
    assert output[1].primary is False


def test_k8s_registry_set_primary(mocker) -> None:
    mock_kube_interface = mocker.patch(
        "spark8t.kube_interface.lightkube.LightKubeInterface"
    )
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
    assert registry.set_primary(f"{namespace2}:{name2}") == f"{namespace2}:{name2}"

    mock_kube_interface.remove_label.assert_any_call(
        resource_type="serviceaccount",
        resource_name=name1,
        label=f"{PRIMARY_LABELNAME}",
        namespace=namespace1,
    )

    mock_kube_interface.remove_label.assert_any_call(
        resource_type="rolebinding",
        resource_name=f"{name1}-role-binding",
        label=f"{PRIMARY_LABELNAME}",
        namespace=namespace1,
    )

    mock_kube_interface.set_label.assert_any_call(
        resource_type="serviceaccount",
        resource_name=name2,
        label=f"{PRIMARY_LABELNAME}=True",
        namespace=namespace2,
    )

    mock_kube_interface.set_label.assert_any_call(
        resource_type="rolebinding",
        resource_name=f"{name2}-role-binding",
        label=f"{PRIMARY_LABELNAME}=True",
        namespace=namespace2,
    )


@pytest.mark.parametrize("dry_run", [True, False])
def test_k8s_registry_create(mocker, dry_run: bool) -> None:
    mock_kube_interface = mocker.patch(
        "spark8t.kube_interface.lightkube.LightKubeInterface"
    )
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
    mock_kube_interface.create.return_value = "<manifest>"
    mock_kube_interface.exists.return_value = False

    registry = K8sServiceAccountRegistry(mock_kube_interface)
    assert registry.create(sa3_obj, dry_run=dry_run) == "---\n".join(["<manifest>"] * 4)

    for call in mock_kube_interface.create.call_args_list:
        print(call)

    mock_kube_interface.create.assert_any_call(
        resource_type=KubernetesResourceType.SERVICEACCOUNT,
        resource_name=name3,
        namespace=namespace3,
        username=name3,
        dry_run=dry_run,
    )

    mock_kube_interface.create.assert_any_call(
        resource_type=KubernetesResourceType.ROLE,
        resource_name=f"{name3}-role",
        namespace=namespace3,
        **{"username": f"{name3}"},
        dry_run=dry_run,
    )

    mock_kube_interface.create.assert_any_call(
        resource_type=KubernetesResourceType.ROLEBINDING,
        resource_name=f"{name3}-role-binding",
        namespace=namespace3,
        **{
            "role": f"{name3}-role",
            "serviceaccount": sa3_obj.id,
            "username": name3,
        },
        dry_run=dry_run,
    )

    if not dry_run:
        mock_kube_interface.set_label.assert_any_call(
            resource_type=KubernetesResourceType.SERVICEACCOUNT,
            resource_name=name3,
            label=f"{MANAGED_BY_LABELNAME}={SPARK8S_LABEL}",
            namespace=namespace3,
        )

        mock_kube_interface.set_label.assert_any_call(
            resource_type=KubernetesResourceType.ROLEBINDING,
            resource_name=f"{name3}-role-binding",
            label=f"{MANAGED_BY_LABELNAME}={SPARK8S_LABEL}",
            namespace=namespace3,
        )

        mock_kube_interface.remove_label.assert_any_call(
            resource_type=KubernetesResourceType.SERVICEACCOUNT,
            resource_name=name1,
            label=f"{PRIMARY_LABELNAME}",
            namespace=namespace1,
        )

        mock_kube_interface.remove_label.assert_any_call(
            resource_type=KubernetesResourceType.ROLEBINDING,
            resource_name=f"{name1}-role-binding",
            label=f"{PRIMARY_LABELNAME}",
            namespace=namespace1,
        )

        mock_kube_interface.set_label.assert_any_call(
            resource_type=KubernetesResourceType.SERVICEACCOUNT,
            resource_name=name3,
            label=f"{PRIMARY_LABELNAME}=True",
            namespace=namespace3,
        )

        mock_kube_interface.set_label.assert_any_call(
            resource_type=KubernetesResourceType.ROLEBINDING,
            resource_name=f"{name3}-role-binding",
            label=f"{PRIMARY_LABELNAME}=True",
            namespace=namespace3,
        )


def test_k8s_registry_delete(mocker) -> None:
    mock_kube_interface = mocker.patch(
        "spark8t.kube_interface.lightkube.LightKubeInterface"
    )
    data = {"k": "v"}
    mock_kube_interface.get_secret.return_value = {"data": data}

    name2 = str(uuid.uuid4())
    namespace2 = str(uuid.uuid4())

    mock_kube_interface.delete.return_value = 0

    registry = K8sServiceAccountRegistry(mock_kube_interface)

    assert registry.delete(f"{namespace2}:{name2}") == f"{namespace2}:{name2}"
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
