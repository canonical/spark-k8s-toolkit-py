"""Parameters module."""

import logging
from argparse import ArgumentParser, Namespace
from typing import Callable

from spark8t.cli import defaults
from spark8t.services import AbstractKubeInterface, KubeInterface, LightKube
from spark8t.utils import DEFAULT_LOGGING_FILE, config_from_file, environ


def parse_arguments_with(
    parsers: list[Callable[[ArgumentParser], ArgumentParser]],
    base_parser: ArgumentParser | None = None,
):
    """
    Specify a chain of parsers to help parse the list of arguments to main.

    :param parsers: List of parsers to be applied.
    :param namespace: Namespace to be used for parsing.
    """
    from functools import reduce

    return reduce(
        lambda x, f: f(x), parsers, base_parser if base_parser else ArgumentParser()
    )


def add_logging_arguments(parser: ArgumentParser) -> ArgumentParser:
    """
    Add logging argument parsing to the existing parser context.

    :param parser: Input parser to decorate with parsing support for logging args.
    """
    parser.add_argument(
        "--log-level",
        choices=["INFO", "WARN", "ERROR", "DEBUG"],
        default="WARN",
        help="Set the log level of the logging",
    )
    parser.add_argument(
        "--log-conf-file",
        help="Provide a log configuration file",
    )

    return parser


def add_ignore_integration_hub(parser: ArgumentParser) -> ArgumentParser:
    """
    Add option to exclude the configuration provided by the Spark Integration Hub.

    :param parser: Input parser to decorate with parsing support for logging args.
    """
    parser.add_argument(
        "--ignore-integration-hub",
        action="store_true",
        help="Ignore the configuration provided by Spark Integration Hub Charm.",
    )

    return parser


def spark_user_parser(parser: ArgumentParser) -> ArgumentParser:
    """
    Add Spark user related argument parsing to the existing parser context.

    :param parser: Input parser to decorate with parsing support for Spark params.
    """
    parser.add_argument(
        "--username",
        default="spark",
        type=str,
        help="Service account name to use other than primary.",
    )
    parser.add_argument(
        "--namespace",
        default="default",
        type=str,
        help="Namespace of service account name to use other than primary.",
    )
    return parser


def k8s_parser(parser: ArgumentParser) -> ArgumentParser:
    """
    Add K8s related argument parsing to the existing parser context.

    :param parser: Input parser to decorate with parsing support for Spark params.
    """
    parser.add_argument(
        "--master", default=None, type=str, help="Kubernetes control plane uri."
    )
    parser.add_argument(
        "--kubeconfig", default=None, type=str, help="Kubernetes configuration file"
    )
    parser.add_argument(
        "--context", default=None, type=str, help="Kubernetes context to be used"
    )
    parser.add_argument(
        "--backend",
        default="kubectl",
        choices=["kubectl", "lightkube"],
        type=str,
        help="Kind of backend to be used for talking to K8s",
    )
    return parser


def add_config_arguments(parser: ArgumentParser) -> ArgumentParser:
    """
    Add arguments to provide extra configurations for the spark properties.

    :param parser: Input parser to decorate with parsing support for deploy arguments.
    """
    parser.add_argument(
        "--properties-file",
        default=None,
        type=str,
        help="Spark default configuration properties file.",
    )
    parser.add_argument(
        "--conf",
        action="append",
        type=str,
        help="Config properties to be added to the service account.",
    )
    return parser


def add_deploy_arguments(parser: ArgumentParser) -> ArgumentParser:
    """
    Add deployment related argument parsing to the existing parser context.

    :param parser: Input parser to decorate with parsing support for deploy arguments.
    """
    parser.add_argument(
        "--deploy-mode",
        default="cluster",
        type=str,
        help="Deployment mode for job submission. Default is 'client'.",
        choices=["client", "cluster"],
    )
    return parser


def get_kube_interface(args: Namespace) -> AbstractKubeInterface:
    """Get configured kube interface."""
    _class = LightKube if args.backend == "lightkube" else KubeInterface

    return _class(
        args.kubeconfig or defaults.kube_config, defaults, context_name=args.context
    )


def setup_logging(
    log_level: str, config_file: str | None, logger_name: str | None = None
) -> logging.Logger:
    """Set up logging from configuration file."""
    with environ(LOG_LEVEL=log_level) as _:
        config_from_file(config_file or DEFAULT_LOGGING_FILE)
    return logging.getLogger(logger_name) if logger_name else logging.root
