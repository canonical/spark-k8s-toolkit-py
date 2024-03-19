import os
import subprocess
import uuid

import pytest
from lightkube.resources.core_v1 import Namespace

from spark8t.domain import Defaults
from spark8t.services import K8sServiceAccountRegistry, KubeInterface, LightKube

integration_test_flag = bool(int(os.environ.get("IE_TEST", "0")))


@pytest.fixture
def integration_test():
    if not integration_test_flag:
        pytest.skip(
            reason="Integration test, to be skipped when running unittests",
        )


@pytest.fixture
def kubeconfig():
    return {"KUBECONFIG": f"{os.environ['HOME']}/.kube/config"}


@pytest.fixture
def defs_with_kubeconf(kubeconfig):
    return Defaults(dict(os.environ) | kubeconfig)


def _get_kube_namespaces(interface):
    ns_data = interface.exec("get namespaces --no-headers -o name")
    return [item["metadata"]["name"] for item in ns_data["items"]]


@pytest.fixture
def kubeinterface(defs_with_kubeconf):
    interface = KubeInterface(defs_with_kubeconf.kube_config, defs_with_kubeconf)
    ns_before = _get_kube_namespaces(interface)
    yield interface
    ns_after = _get_kube_namespaces(interface)
    for ns in set(ns_after) - set(ns_before):
        interface.delete("namespace", ns)


def _get_lightkube_namespaces(iface):
    return [ns.metadata.name for ns in iface.client.list(Namespace)]


@pytest.fixture
def lightkubeinterface(defs_with_kubeconf):
    interface = LightKube(defs_with_kubeconf.kube_config, defs_with_kubeconf)
    ns_before = _get_lightkube_namespaces(interface)
    yield interface
    ns_after = _get_lightkube_namespaces(interface)
    for ns in set(ns_after) - set(ns_before):
        interface.client.delete(Namespace, name=ns)


def _clearnup_registry(registry):
    [registry.delete(account.id) for account in registry.all()]


@pytest.fixture
def kube_registry(kubeinterface):
    registry = K8sServiceAccountRegistry(kubeinterface)
    yield registry
    _clearnup_registry(registry)


@pytest.fixture
def lightkube_registry(lightkubeinterface):
    registry = K8sServiceAccountRegistry(lightkubeinterface)
    yield registry
    _clearnup_registry(registry)


@pytest.fixture
def namespace():
    """A temporary K8S namespace gets cleaned up automatically"""
    namespace_name = str(uuid.uuid4())
    create_command = ["kubectl", "create", "namespace", namespace_name]
    subprocess.run(create_command, check=True)
    yield namespace_name
    destroy_command = ["kubectl", "delete", "namespace", namespace_name]
    subprocess.run(destroy_command, check=True)
