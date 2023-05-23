from argparse import ArgumentParser, Namespace
from typing import Callable, List, Optional

from spark8t.cli import defaults
from spark8t.services import AbstractKubeInterface, KubeInterface, LightKube


def parse_arguments_with(
    parsers: List[Callable[[ArgumentParser], ArgumentParser]],
    base_parser: Optional[ArgumentParser] = None,
):
    """
    Specify a chain of parsers to help parse the list of arguments to main

    :param parsers: List of parsers to be applied.
    :param namespace: Namespace to be used for parsing.
    """
    from functools import reduce

    return reduce(
        lambda x, f: f(x), parsers, base_parser if base_parser else ArgumentParser()
    )


def add_logging_arguments(parser: ArgumentParser) -> ArgumentParser:
    """
    Add logging argument parsing to the existing parser context

    :param parser: Input parser to decorate with parsing support for logging args.
    """
    parser.add_argument(
        "--log-level",
        choices=["INFO", "WARN", "ERROR", "DEBUG"],
        default="ERROR",
        help="Set the log level of the logging",
    )

    return parser


def spark_user_parser(parser: ArgumentParser) -> ArgumentParser:
    """
    Add Spark user related argument parsing to the existing parser context

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
    Add K8s related argument parsing to the existing parser context

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
    Add arguments to provide extra configurations for the spark properties

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
    Add deployment related argument parsing to the existing parser context

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
    return (
        LightKube(args.kubeconfig or defaults.kube_config, defaults)
        if args.backend == "lightkube"
        else KubeInterface(
            args.kubeconfig or defaults.kube_config, context_name=args.context
        )
    )
