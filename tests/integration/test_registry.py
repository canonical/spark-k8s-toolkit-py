import uuid

import pytest

from spark8t.domain import KubernetesResourceType, PropertyFile, ServiceAccount
from spark8t.kube_interface.lightkube import LightKubeInterface
from spark8t.registry.k8s import K8sServiceAccountRegistry


@pytest.mark.usefixtures("integration_test")
@pytest.mark.parametrize(
    "namespace, user",
    [("default-a-namespace", "spark"), ("spark-a-namespace", "spark-user")],
)
def test_registry_io(
    kubeinterface: LightKubeInterface,
    registry: K8sServiceAccountRegistry,
    namespace: str,
    user: str,
) -> None:
    kubeinterface.create(
        resource_type=KubernetesResourceType.NAMESPACE, resource_name=namespace
    )

    service_account = ServiceAccount(
        user,
        namespace,
        kubeinterface.api_server,
        primary=True,
        extra_confs=PropertyFile(
            {"my-key": "my-value", "my-strange-key_*.@.%.$": "my-strange-value_*.@.%.$"}
        ),
    )

    registry.create(service_account)

    assert len(registry.all(namespace=namespace)) == 1

    retrieved_service_account = registry.get(service_account.id)

    assert retrieved_service_account is not None
    assert service_account.id == retrieved_service_account.id
    assert service_account.name == retrieved_service_account.name
    assert service_account.namespace == retrieved_service_account.namespace
    assert service_account.primary == retrieved_service_account.primary
    assert (
        service_account.extra_confs.props == retrieved_service_account.extra_confs.props
    )

    # Assert that a non-existing service account id provide None
    retrieved_service_account = registry.get("non-existing:non-existing")
    assert retrieved_service_account is None


@pytest.mark.usefixtures("integration_test")
@pytest.mark.parametrize(
    "namespace, username",
    [("default-b-namespace", "spark"), ("spark-b-namespace", "spark-user")],
)
def test_registry_change_primary_account(
    kubeinterface: LightKubeInterface,
    registry: K8sServiceAccountRegistry,
    namespace: str,
    username: str,
) -> None:
    kubeinterface.create(
        resource_type=KubernetesResourceType.NAMESPACE, resource_name=namespace
    )

    sa1 = ServiceAccount(
        f"{username}-1",
        namespace,
        kubeinterface.api_server,
        primary=True,
        extra_confs=PropertyFile({"k1": "v1"}),
    )
    sa2 = ServiceAccount(
        f"{username}-2",
        namespace,
        kubeinterface.api_server,
        primary=False,
        extra_confs=PropertyFile({"k2": "v2"}),
    )
    registry.create(sa1)
    registry.create(sa2)

    assert (primary := registry.get_primary(namespace)) is not None
    assert primary.id == sa1.id

    registry.set_primary(sa2.id, namespace)

    assert (primary := registry.get_primary(namespace)) is not None
    assert primary.id == sa2.id


@pytest.mark.xfail(
    reason="[BUG]: No namespace means ALL for KubeInterface, 'default' for LightKube..."
)
def test_registry_all(
    kubeinterface: LightKubeInterface,
    registry: K8sServiceAccountRegistry,
) -> None:
    kubeinterface.create(
        resource_type=KubernetesResourceType.NAMESPACE, resource_name="namespace-1"
    )
    kubeinterface.create(
        resource_type=KubernetesResourceType.NAMESPACE, resource_name="namespace-2"
    )

    sa1 = ServiceAccount(
        "username-1",
        "namespace-1",
        kubeinterface.api_server,
        primary=True,
        extra_confs=PropertyFile({"k1": "v1"}),
    )
    sa2 = ServiceAccount(
        "username-2",
        "namespace-2",
        kubeinterface.api_server,
        primary=False,
        extra_confs=PropertyFile({"k2": "v2"}),
    )
    registry.create(sa1)
    registry.create(sa2)

    assert len(registry.all("namespace-1")) == 1
    assert len(registry.all("namespace-2")) == 1
    assert len(registry.all()) == 2


@pytest.mark.usefixtures("integration_test")
def test_merge_configurations() -> None:
    k1 = str(uuid.uuid4())
    v11 = str(uuid.uuid4())
    v12 = str(uuid.uuid4())
    v13 = str(uuid.uuid4())
    k2 = "spark.driver.extraJavaOptions"
    v21 = str(uuid.uuid4())
    v22 = str(uuid.uuid4())
    v23 = str(uuid.uuid4())

    props1 = PropertyFile(
        {k1: v11, k2: f"-Dscala.shell.histfile={v21}", "key1": "value1"}
    )
    props2 = PropertyFile(
        {k1: v12, k2: f"-Dscala.shell.histfile={v22}", "key2": "value2"}
    )
    props3 = PropertyFile(
        {k1: v13, k2: f"-Dscala.shell.histfile={v23}", "key3": "value3"}
    )

    merged_props = props1 + props2 + props3

    expected_merged_props = PropertyFile(
        {
            k1: v13,
            k2: f"-Dscala.shell.histfile={v23}",
            "key1": "value1",
            "key2": "value2",
            "key3": "value3",
        }
    )

    assert merged_props.props == expected_merged_props.props
