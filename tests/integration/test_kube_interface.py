import os
from time import sleep

import pytest

from spark8t.domain import KubernetesResourceType, PropertyFile
from spark8t.kube_interface.lightkube import LightKubeInterface
from spark8t.utils import umask_named_temporary_file


@pytest.mark.parametrize(
    "resource_type, resource_name, namespace",
    [
        (KubernetesResourceType.NAMESPACE, "spark-namespace", None),
        (KubernetesResourceType.SERVICEACCOUNT, "spark-sa", "default"),
    ],
)
def test_create_exists_delete(
    kubeinterface: LightKubeInterface,
    resource_type: KubernetesResourceType,
    resource_name: str,
    namespace: str,
) -> None:
    kubeinterface.create(resource_type, resource_name, namespace)

    assert kubeinterface.exists(resource_type, resource_name, namespace)

    kubeinterface.delete(resource_type, resource_name, namespace)

    if resource_type == KubernetesResourceType.NAMESPACE:
        sleep(15)

    assert not kubeinterface.exists(resource_type, resource_name, namespace)


def test_create_exists_delete_secret(
    kubeinterface: LightKubeInterface, namespace: str
) -> None:
    secret_name = "my-secret"

    property_file = PropertyFile({"key": "value"})

    with umask_named_temporary_file(
        mode="w",
        prefix="spark-dynamic-conf-k8s-",
        suffix=".conf",
        dir=os.path.expanduser("~"),
    ) as t:
        property_file.write(t.file)

        t.flush()

        kubeinterface.create(
            KubernetesResourceType.SECRET_GENERIC,
            secret_name,
            namespace=namespace,
            dry_run=False,
            **{"from-env-file": str(t.name)},
        )

    assert kubeinterface.exists(
        KubernetesResourceType.SECRET_GENERIC, secret_name, namespace
    )

    kubeinterface.delete(KubernetesResourceType.SECRET_GENERIC, secret_name, namespace)

    assert not kubeinterface.exists(
        KubernetesResourceType.SECRET_GENERIC, secret_name, namespace
    )


def test_delete_secret_content(
    kubeinterface: LightKubeInterface, namespace: str
) -> None:
    secret_name = "my-secret"

    property_file = PropertyFile({"key": "value"})

    with umask_named_temporary_file(
        mode="w",
        prefix="spark-dynamic-conf-k8s-",
        suffix=".conf",
        dir=os.path.expanduser("~"),
    ) as t:
        property_file.write(t.file)

        t.flush()

        kubeinterface.create(
            KubernetesResourceType.SECRET_GENERIC,
            secret_name,
            namespace=namespace,
            dry_run=False,
            **{"from-env-file": str(t.name)},
        )

    assert kubeinterface.exists(
        KubernetesResourceType.SECRET_GENERIC, secret_name, namespace
    )

    kubeinterface.delete_secret_content(secret_name, namespace)

    kubeinterface.exists(KubernetesResourceType.SECRET_GENERIC, secret_name, namespace)

    secret_content = kubeinterface.get_secret(secret_name, namespace)["data"]

    print(f"Secret content: {secret_content}")
    assert len(secret_content.keys()) == 0

    kubeinterface.add_secret_content(secret_name, namespace, property_file)
    secret_content = kubeinterface.get_secret(secret_name, namespace)["data"]

    print(f"Secret content: {secret_content}")
    assert len(secret_content.keys()) == 1

    kubeinterface.add_secret_content(secret_name, namespace, property_file)
    secret_content = kubeinterface.get_secret(secret_name, namespace)["data"]

    print(f"Secret content: {secret_content}")
    assert len(secret_content.keys()) == 1

    property_file_1 = PropertyFile({"key": "value", "key1": "value"})
    kubeinterface.add_secret_content(secret_name, namespace, property_file_1)

    secret_content = kubeinterface.get_secret(secret_name, namespace)["data"]

    print(f"Secret content: {secret_content}")
    assert len(secret_content.keys()) == 2

    kubeinterface.delete(KubernetesResourceType.SECRET_GENERIC, secret_name, namespace)

    assert not kubeinterface.exists(
        KubernetesResourceType.SECRET_GENERIC, secret_name, namespace
    )
