import argparse
import logging
import unittest
from argparse import ArgumentParser

from spark_client.cli.service_account_registry import (
    create_service_account_registry_parser,
)
from spark_client.utils import (
    add_config_arguments,
    add_deploy_arguments,
    add_logging_arguments,
    k8s_parser,
    parse_arguments_with,
    spark_user_parser,
)
from tests import TestCase


class TestArgumentParsingPySpark(TestCase):
    def setUp(self) -> None:
        self.shell_parser = parse_arguments_with(
            [
                add_logging_arguments,
                k8s_parser,
                spark_user_parser,
                add_config_arguments,
            ],
            argparse.ArgumentParser(exit_on_error=False),
        )
        self.submit_parser = parse_arguments_with(
            [
                add_logging_arguments,
                k8s_parser,
                spark_user_parser,
                add_deploy_arguments,
                add_config_arguments,
            ],
            argparse.ArgumentParser(exit_on_error=False),
        )

    def test_logging(self):
        args, extra_args = self.shell_parser.parse_known_args(["--log-level", "INFO"])
        self.assertEqual(args.log_level, "INFO")

        self.assertRaises(
            argparse.ArgumentError,
            lambda: self.shell_parser.parse_known_args(["--log-level", "NON-EXISTING"]),
        )

    def test_base_config(self):
        args, extra_args = self.shell_parser.parse_known_args(
            [
                "--conf",
                "mykey=myvalue",
                "--conf",
                "mykey2=myvalue2",
                "--properties-file",
                "my-property-file",
            ]
        )
        self.assertEqual(len(args.conf), 2)
        self.assertEqual(args.properties_file, "my-property-file")

    def test_shell_defaults(self):
        args, extra_args = self.shell_parser.parse_known_args()
        self.assertEqual(args.namespace, "default")
        self.assertEqual(args.username, "spark")

    def test_shell(self):
        args, extra_args = self.shell_parser.parse_known_args(
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
        self.assertEqual(args.master, "my-master")
        self.assertEqual(args.username, "spark2")
        self.assertEqual(args.namespace, "ns")
        self.assertEqual(args.kubeconfig, "my-file")
        self.assertEqual(args.context, "my-context")

    def test_submit_defaults(self):
        args, extra_args = self.submit_parser.parse_known_args()
        self.assertEqual(args.namespace, "default")
        self.assertEqual(args.username, "spark")
        self.assertEqual(args.deploy_mode, "cluster")

    def test_submit(self):
        args, extra_args = self.submit_parser.parse_known_args(
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
        self.assertEqual(args.master, "my-master")
        self.assertEqual(args.username, "spark2")
        self.assertEqual(args.namespace, "ns")
        self.assertEqual(args.kubeconfig, "my-file")
        self.assertEqual(args.context, "my-context")


class TestArgumentParsingServiceAccountRegistry(TestCase):
    def setUp(self) -> None:
        self.parser = create_service_account_registry_parser(
            ArgumentParser(description="Spark Client Setup", exit_on_error=False)
        )

    def test_create(self):
        args = self.parser.parse_args(
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

        self.assertEqual(args.action, "create")
        self.assertEqual(args.username, "spark")
        self.assertEqual(args.namespace, "default")
        self.assertEqual(len(args.conf), 2)

    def test_delete(self):
        args = self.parser.parse_args(
            ["delete", "--username", "spark-2", "--namespace", "ns2"]
        )

        self.assertEqual(args.action, "delete")
        self.assertEqual(args.username, "spark-2")
        self.assertEqual(args.namespace, "ns2")

    def test_delete_conf(self):
        args = self.parser.parse_args(
            ["clear-config", "--username", "spark-2", "--namespace", "ns2"]
        )

        self.assertEqual(args.action, "clear-config")
        self.assertEqual(args.username, "spark-2")
        self.assertEqual(args.namespace, "ns2")

    def test_get_conf(self):
        args = self.parser.parse_args(["get-config"])

        self.assertEqual(args.action, "get-config")
        self.assertEqual(args.username, "spark")
        self.assertEqual(args.namespace, "default")

    def test_add_conf(self):
        args = self.parser.parse_args(
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

        self.assertEqual(args.action, "add-config")
        self.assertEqual(len(args.conf), 1)
        self.assertEqual(args.conf[0], "mykey=myvalue")
        self.assertEqual(args.username, "spark-3")
        self.assertEqual(args.namespace, "default")
        self.assertEqual(args.properties_file, "my-file")

    def test_list(self):
        args = self.parser.parse_args(["list", "--kubeconfig", "my-kube-config"])

        self.assertEqual(args.action, "list")
        self.assertEqual(args.kubeconfig, "my-kube-config")

        args = self.parser.parse_args(["list"])

        self.assertEqual(args.action, "list")
        self.assertEqual(args.kubeconfig, None)

    def test_primary(self):
        args = self.parser.parse_args(["get-primary", "--master", "my-k8s-api-server"])

        self.assertEqual(args.action, "get-primary")
        self.assertEqual(args.master, "my-k8s-api-server")

        args = self.parser.parse_args(["get-primary"])

        self.assertEqual(args.action, "get-primary")
        self.assertEqual(args.master, None)


if __name__ == "__main__":
    logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level="DEBUG")
    unittest.main()
