import uuid
from time import sleep

import pytest
from lightkube.models.meta_v1 import ObjectMeta, OwnerReference
from lightkube.resources.core_v1 import Secret
from lightkube.resources.core_v1 import ServiceAccount as LightKubeServiceAccount
from tenacity import Retrying, stop_after_delay, wait_fixed

from spark8t.domain import KubernetesResourceType, PropertyFile
from spark8t.kube_interface.lightkube import LightKubeInterface


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

    kubeinterface.create(
        KubernetesResourceType.SECRET_GENERIC,
        secret_name,
        namespace=namespace,
        dry_run=False,
        key="value",
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

    secret_content = {"key": "value"}
    property_file = PropertyFile(secret_content)

    kubeinterface.create(
        KubernetesResourceType.SECRET_GENERIC,
        secret_name,
        namespace=namespace,
        dry_run=False,
        **secret_content,
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


def test_delete_service_account_cascades_owner_references(
    kubeinterface: LightKubeInterface, namespace: str
) -> None:
    sa_name = f"sa-{uuid.uuid4()}"
    kubeinterface.create(KubernetesResourceType.SERVICEACCOUNT, sa_name, namespace)

    assert kubeinterface.exists(
        KubernetesResourceType.SERVICEACCOUNT, sa_name, namespace
    )

    sa = kubeinterface.client.get(
        res=LightKubeServiceAccount, name=sa_name, namespace=namespace
    )
    assert sa.metadata is not None
    assert sa.metadata.uid is not None

    owner_ref = OwnerReference(
        apiVersion="v1",
        kind="ServiceAccount",
        name=sa_name,
        uid=sa.metadata.uid,
    )

    dependent_secret_name = f"dep-secret-{uuid.uuid4()}"
    dependent_secret = Secret(
        metadata=ObjectMeta(
            name=dependent_secret_name,
            namespace=namespace,
            ownerReferences=[owner_ref],
        ),
        data={},
    )
    kubeinterface.client.create(dependent_secret)

    assert kubeinterface.exists(
        KubernetesResourceType.SECRET_GENERIC, dependent_secret_name, namespace
    )

    # Deleting the service account should cascade in the background
    # and delete dependent resources referencing it via ownerReferences
    kubeinterface.delete(KubernetesResourceType.SERVICEACCOUNT, sa_name, namespace)

    assert not kubeinterface.exists(
        KubernetesResourceType.SERVICEACCOUNT, sa_name, namespace
    )

    for attempt in Retrying(
        stop=stop_after_delay(30), wait=wait_fixed(1), reraise=True
    ):
        with attempt:
            assert not kubeinterface.exists(
                KubernetesResourceType.SECRET_GENERIC, dependent_secret_name, namespace
            ), f"Dependent resource {dependent_secret_name} was not garbage collected"
