#!/usr/bin/env python3

import re
from typing import Optional

from spark8t.cli.params import (
    add_config_arguments,
    add_logging_arguments,
    defaults,
    get_kube_interface,
    k8s_parser,
    parse_arguments_with,
    spark_user_parser,
)
from spark8t.domain import ServiceAccount
from spark8t.services import K8sServiceAccountRegistry, SparkInterface
from spark8t.utils import setup_logging

if __name__ == "__main__":
    args, extra_args = parse_arguments_with(
        [add_logging_arguments, k8s_parser, spark_user_parser, add_config_arguments]
    ).parse_known_args()

    logger = setup_logging(
        args.log_level, args.log_conf_file, "spark8t.cli.spark_shell"
    )

    kube_interface = get_kube_interface(args)

    registry = K8sServiceAccountRegistry(
        kube_interface.select_by_master(re.compile("^k8s://").sub("", args.master))
        if args.master is not None
        else kube_interface
    )

    service_account: Optional[ServiceAccount] = (
        registry.get_primary()
        if args.username is None and args.namespace is None
        else registry.get(f"{args.namespace or 'default'}:{args.username or 'spark'}")
    )

    if service_account is None:
        raise ValueError("Service account provided does not exist.")

    SparkInterface(
        service_account=service_account,
        kube_interface=kube_interface,
        defaults=defaults,
    ).spark_shell(args.conf, args.properties_file, extra_args)
