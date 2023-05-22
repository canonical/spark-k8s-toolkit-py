import os
from time import sleep
from unittest import TestCase

from parameterized import parameterized

from spark8t.domain import Defaults, KubernetesResourceType, PropertyFile
from spark8t.services import AbstractKubeInterface, KubeInterface, LightKube
from spark8t.utils import umask_named_temporary_file


class TestKubeInterface(TestCase):
    kube_interface: AbstractKubeInterface
    defaults = Defaults(
        dict(os.environ) | {"KUBECONFIG": f"{os.environ['HOME']}/.kube/config"}
    )

    def get_kube_interface(self):
        return KubeInterface(self.defaults.kube_config)

    @parameterized.expand(
        [
            (KubernetesResourceType.NAMESPACE, "spark-namespace", None),
            (KubernetesResourceType.SERVICEACCOUNT, "spark-sa", "default"),
        ]
    )
    # @integration_test
    def test_create_exists_delete(self, resource_type, resource_name, namespace):
        k1 = self.get_kube_interface()

        assert not k1.exists(resource_type, resource_name, namespace)

        k1.create(resource_type, resource_name, namespace)

        assert k1.exists(resource_type, resource_name, namespace)

        k1.delete(resource_type, resource_name, namespace)

        if resource_type == KubernetesResourceType.NAMESPACE:
            sleep(15)

        assert not k1.exists(resource_type, resource_name, namespace)

    def test_create_exists_delete_secret(self):
        secret_name = "my-secret"
        namespace = "default"

        property_file = PropertyFile({"key": "value"})

        k1 = self.get_kube_interface()

        assert not k1.exists(
            KubernetesResourceType.SECRET_GENERIC, secret_name, namespace
        )

        with umask_named_temporary_file(
            mode="w", prefix="spark-dynamic-conf-k8s-", suffix=".conf"
        ) as t:
            property_file.write(t.file)

            t.flush()

            k1.create(
                KubernetesResourceType.SECRET_GENERIC,
                secret_name,
                namespace=namespace,
                **{"from-env-file": str(t.name)},
            )

        assert k1.exists(KubernetesResourceType.SECRET_GENERIC, secret_name, namespace)

        k1.delete(KubernetesResourceType.SECRET_GENERIC, secret_name, namespace)

        assert not k1.exists(
            KubernetesResourceType.SECRET_GENERIC, secret_name, namespace
        )


class TestLightKube(TestKubeInterface):
    def get_kube_interface(self):
        return LightKube(self.defaults.kube_config, self.defaults)
