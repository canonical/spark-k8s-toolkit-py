import uuid
from unittest import TestCase

from parameterized import parameterized

from spark8t.domain import Defaults, PropertyFile, ServiceAccount
from spark8t.services import (
    AbstractServiceAccountRegistry,
    K8sServiceAccountRegistry,
    KubeInterface,
)
from tests import integration_test


class TestRegistry(TestCase):
    kube_interface: KubeInterface
    defaults = Defaults()

    @classmethod
    def setUpClass(cls) -> None:
        cls.kube_interface = KubeInterface(cls.defaults.kube_config)

    def get_registry(self) -> AbstractServiceAccountRegistry:
        return K8sServiceAccountRegistry(self.kube_interface)

    def setUp(self) -> None:
        # Make sure there are no service account before each test is run
        registry = self.cleanup_registry(self.get_registry())
        self.assertEqual(len(registry.all()), 0)

    def tearDown(self) -> None:
        # Make sure there are no service account before each test is run
        registry = self.cleanup_registry(self.get_registry())
        self.assertEqual(len(registry.all()), 0)

    @staticmethod
    def cleanup_registry(registry: AbstractServiceAccountRegistry):
        [registry.delete(account.id) for account in registry.all()]
        return registry

    @parameterized.expand(
        [("default-namespace", "spark"), ("spark-namespace", "spark-user")]
    )
    @integration_test
    def test_registry_io(self, namespace, user):
        registry = self.get_registry()

        self.assertEqual(len(registry.all()), 0)

        self.kube_interface.create(resource_type="namespace", resource_name=namespace)

        service_account = ServiceAccount(
            user,
            namespace,
            self.kube_interface.api_server,
            primary=True,
            extra_confs=PropertyFile({"my-key": "my-value"}),
        )

        registry.create(service_account)

        self.assertEqual(len(registry.all()), 1)

        retrieved_service_account = registry.get(service_account.id)

        self.assertEqual(service_account.id, retrieved_service_account.id)
        self.assertEqual(service_account.name, retrieved_service_account.name)
        self.assertEqual(service_account.namespace, retrieved_service_account.namespace)
        self.assertEqual(service_account.primary, retrieved_service_account.primary)
        self.assertEqual(
            service_account.extra_confs.props,
            retrieved_service_account.extra_confs.props,
        )

        registry.delete(service_account.id)
        self.kube_interface.delete("namespace", namespace)

    @parameterized.expand(
        [("default-namespace", "spark"), ("spark-namespace", "spark-user")]
    )
    @integration_test
    def test_registry_change_primary_account(self, namespace, username):
        self.kube_interface.create(resource_type="namespace", resource_name=namespace)

        registry = self.get_registry()
        self.assertEqual(len(registry.all()), 0)
        sa1 = ServiceAccount(
            f"{username}-1",
            namespace,
            self.kube_interface.api_server,
            primary=True,
            extra_confs=PropertyFile({"k1": "v1"}),
        )
        sa2 = ServiceAccount(
            f"{username}-2",
            namespace,
            self.kube_interface.api_server,
            primary=False,
            extra_confs=PropertyFile({"k2": "v2"}),
        )
        registry.create(sa1)
        registry.create(sa2)

        self.assertEqual(registry.get_primary().id, sa1.id)

        registry.set_primary(sa2.id)

        self.assertEqual(registry.get_primary().id, sa2.id)

        registry.delete(sa1.id)
        registry.delete(sa2.id)

        self.kube_interface.delete("namespace", namespace)

    @integration_test
    def test_merge_configurations(self):
        registry = self.get_registry()
        self.assertEqual(len(registry.all()), 0)
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
                k2: f" -Dscala.shell.histfile={v23}",
                "key1": "value1",
                "key2": "value2",
                "key3": "value3",
            }
        )

        self.assertEqual(merged_props.props, expected_merged_props.props)

    @integration_test
    def test_kube_interface(self):
        context = str(uuid.uuid4())
        kubectl_cmd = str(uuid.uuid4())

        k = self.kube_interface.autodetect()
        self.assertEqual(k.context_name, "microk8s")
        self.assertEqual(k.cluster.get("server"), "https://127.0.0.1:16443")
        k2 = k.select_by_master("https://127.0.0.1:16443")
        self.assertEqual(k2.context_name, "microk8s")
        self.assertEqual(k.with_context(context).context_name, context)
        self.assertEqual(k.with_kubectl_cmd(kubectl_cmd).kubectl_cmd, kubectl_cmd)
