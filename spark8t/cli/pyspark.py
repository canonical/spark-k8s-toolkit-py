#!/usr/bin/env python3
"""Pyspark module."""

import os
import re
from argparse import Namespace
from logging import Logger

from spark8t.cli import defaults
from spark8t.cli.params import (
    add_config_arguments,
    add_ignore_integration_hub,
    add_logging_arguments,
    k8s_parser,
    parse_arguments_with,
    spark_user_parser,
)
from spark8t.domain import ServiceAccount
from spark8t.exceptions import AccountNotFound, PrimaryAccountNotFound
from spark8t.kube_interface.lightkube import LightKubeInterface
from spark8t.registry.k8s import K8sServiceAccountRegistry
from spark8t.spark_interface import SparkInterface
from spark8t.utils import PropertyFile, setup_logging


def main(args: Namespace, logger: Logger):
    """Pyspark main entrypoint."""
    kubeconfig = os.path.expandvars(args.kubeconfig) if args.kubeconfig else None
    context_name = os.path.expandvars(args.context) if args.context else None
    master = os.path.expandvars(args.master) if args.master else None
    namespace = os.path.expandvars(args.namespace) if args.namespace else None
    username = os.path.expandvars(args.username) if args.username else None
    confs = [os.path.expandvars(conf) for conf in args.conf] if args.conf else []

    print(
        f"Expanded args: kubeconfig={kubeconfig}, context={context_name}, master={master}, namespace={namespace}, username={username}, confs={confs}"
    )
    logger.info(
        f"Expanded args: kubeconfig={kubeconfig}, context={context_name}, master={master}, namespace={namespace}, username={username}, confs={confs}"
    )

    properties_file = (
        os.path.expandvars(args.properties_file) if args.properties_file else None
    )

    kube_interface = LightKubeInterface(
        kubeconfig or defaults.kube_config, defaults, context_name=context_name
    )

    registry = K8sServiceAccountRegistry(
        kube_interface.select_by_master(re.compile("^k8s://").sub("", master))
        if master is not None
        else kube_interface
    )
    print(f"Using kube interface with API server: {registry.kube_interface.api_server}")
    logger.info(
        f"Using kube interface with API server: {registry.kube_interface.api_server}"
    )

    service_account: ServiceAccount | None = (
        registry.get_primary()
        if username is None and namespace is None
        else registry.get(f"{namespace or 'default'}:{username or 'spark'}")
    )

    print(f"Retrieved service account: {service_account}")
    logger.info(f"Retrieved service account: {service_account}")

    if service_account is None:
        raise (AccountNotFound(username) if username else PrimaryAccountNotFound())

    if args.ignore_integration_hub:
        service_account.integration_hub_confs = PropertyFile.empty()

    SparkInterface(
        service_account=service_account,
        kube_interface=kube_interface,
        defaults=defaults,
    ).pyspark_shell(confs, properties_file, extra_args)


if __name__ == "__main__":
    args, extra_args = parse_arguments_with(
        [
            add_logging_arguments,
            k8s_parser,
            spark_user_parser,
            add_config_arguments,
            add_ignore_integration_hub,
        ]
    ).parse_known_args()

    logger = setup_logging(args.log_level, args.log_conf_file, "spark8t.cli.pyspark")

    try:
        main(args, logger)
        exit(0)
    except (AccountNotFound, PrimaryAccountNotFound) as e:
        logger.error(str(e))
        exit(1)
    except Exception as e:
        raise e
