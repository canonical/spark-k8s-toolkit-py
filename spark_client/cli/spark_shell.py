#!/usr/bin/env python3

import logging
import re
from typing import Optional

from spark_client.cli import defaults
from spark_client.domain import ServiceAccount
from spark_client.services import K8sServiceAccountRegistry, LightKube, SparkInterface
from spark_client.utils import (
    add_config_arguments,
    add_logging_arguments,
    k8s_parser,
    parse_arguments_with,
    spark_user_parser,
)

if __name__ == "__main__":
    args, extra_args = parse_arguments_with(
        [add_logging_arguments, k8s_parser, spark_user_parser, add_config_arguments]
    ).parse_known_args()

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(message)s", level=args.log_level
    )

    kube_interface = LightKube(args.kubeconfig or defaults.kube_config, defaults)

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
