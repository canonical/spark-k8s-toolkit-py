import argparse
from argparse import ArgumentParser

import pytest

from spark8t.cli.service_account_registry import create_service_account_registry_parser


def test_logging(shell_parser):
    args, extra_args = shell_parser.parse_known_args(["--log-level", "INFO"])
    assert args.log_level == "INFO"

    with pytest.raises(argparse.ArgumentError):
        shell_parser.parse_known_args(["--log-level", "NON-EXISTING"])


def test_base_config(shell_parser):
    args, extra_args = shell_parser.parse_known_args(
        [
            "--conf",
            "mykey=myvalue",
            "--conf",
            "mykey2=myvalue2",
            "--properties-file",
            "my-property-file",
        ]
    )
    assert len(args.conf) == 2
    assert args.properties_file == "my-property-file"


def test_shell_defaults(shell_parser):
    args, extra_args = shell_parser.parse_known_args()
    assert args.namespace == "default"
    assert args.username == "spark"


def test_shell(shell_parser):
    args, extra_args = shell_parser.parse_known_args(
        [
            "--master",
            "my-master",
            "--username",
            "spark2",
            "--namespace",
            "ns",
            "--kubeconfig",
            "my-file",
            "--context",
            "my-context",
        ]
    )
    assert args.master == "my-master"
    assert args.username == "spark2"
    assert args.namespace == "ns"
    assert args.kubeconfig == "my-file"
    assert args.context == "my-context"


def test_submit_defaults(submit_parser):
    args, extra_args = submit_parser.parse_known_args()
    assert args.namespace == "default"
    assert args.username == "spark"
    assert args.deploy_mode == "cluster"


def test_submit(submit_parser):
    args, extra_args = submit_parser.parse_known_args(
        [
            "--master",
            "my-master",
            "--username",
            "spark2",
            "--namespace",
            "ns",
            "--kubeconfig",
            "my-file",
            "--context",
            "my-context",
        ]
    )
    assert args.master == "my-master"
    assert args.username == "spark2"
    assert args.namespace == "ns"
    assert args.kubeconfig == "my-file"
    assert args.context == "my-context"


@pytest.fixture
def service_account_registry_parser():
    return create_service_account_registry_parser(
        ArgumentParser(description="Spark Client Setup", exit_on_error=False)
    )


def test_create(service_account_registry_parser):
    args = service_account_registry_parser.parse_args(
        [
            "create",
            "--username",
            "spark",
            "--conf",
            "mykey=myvalue",
            "--conf",
            "mykey2=myvalue2",
        ]
    )

    assert args.action == "create"
    assert args.username == "spark"
    assert args.namespace == "default"
    assert len(args.conf) == 2


def test_delete(service_account_registry_parser):
    args = service_account_registry_parser.parse_args(
        ["delete", "--username", "spark-2", "--namespace", "ns2"]
    )

    assert args.action == "delete"
    assert args.username == "spark-2"
    assert args.namespace == "ns2"


def test_delete_conf(service_account_registry_parser):
    args = service_account_registry_parser.parse_args(
        ["clear-config", "--username", "spark-2", "--namespace", "ns2"]
    )

    assert args.action == "clear-config"
    assert args.username == "spark-2"
    assert args.namespace == "ns2"


def test_get_conf(service_account_registry_parser):
    args = service_account_registry_parser.parse_args(["get-config"])

    assert args.action == "get-config"
    assert args.username == "spark"
    assert args.namespace == "default"


def test_add_conf(service_account_registry_parser):
    args = service_account_registry_parser.parse_args(
        [
            "add-config",
            "--username",
            "spark-3",
            "--conf",
            "mykey=myvalue",
            "--properties-file",
            "my-file",
        ]
    )

    assert args.action == "add-config"
    assert len(args.conf) == 1
    assert args.conf[0] == "mykey=myvalue"
    assert args.username == "spark-3"
    assert args.namespace == "default"
    assert args.properties_file == "my-file"


def test_list(service_account_registry_parser):
    args = service_account_registry_parser.parse_args(
        ["list", "--kubeconfig", "my-kube-config"]
    )

    assert args.action == "list"
    assert args.kubeconfig == "my-kube-config"

    args = service_account_registry_parser.parse_args(["list"])

    assert args.action == "list"
    assert args.kubeconfig is None


def test_primary(service_account_registry_parser):
    args = service_account_registry_parser.parse_args(
        ["get-primary", "--master", "my-k8s-api-server"]
    )

    assert args.action == "get-primary"
    assert args.master == "my-k8s-api-server"

    args = service_account_registry_parser.parse_args(["get-primary"])

    assert args.action == "get-primary"
    assert args.master is None
