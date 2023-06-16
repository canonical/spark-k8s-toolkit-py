#!/usr/bin/env python3

from argparse import ArgumentParser
from enum import Enum

from spark8t.cli.params import (
    add_config_arguments,
    add_logging_arguments,
    get_kube_interface,
    k8s_parser,
    parse_arguments_with,
    spark_user_parser,
)
from spark8t.domain import PropertyFile, ServiceAccount
from spark8t.exceptions import NoAccountFound
from spark8t.services import K8sServiceAccountRegistry, parse_conf_overrides
from spark8t.utils import setup_logging


def build_service_account_from_args(args) -> ServiceAccount:
    return ServiceAccount(
        name=args.username,
        namespace=args.namespace,
        api_server=registry.kube_interface.api_server,
        primary=args.primary if hasattr(args, "primary") else False,
    )


class Actions(str, Enum):
    CREATE = "create"
    DELETE = "delete"
    ADD_CONFIG = "add-config"
    REMOVE_CONFIG = "remove-config"
    GET_CONFIG = "get-config"
    CLEAR_CONFIG = "clear-config"
    PRIMARY = "get-primary"
    LIST = "list"


def create_service_account_registry_parser(parser: ArgumentParser):
    base_parser = parse_arguments_with(
        [add_logging_arguments, k8s_parser],
        ArgumentParser(add_help=False),
    )

    subparsers = parser.add_subparsers(dest="action")
    subparsers.required = True

    #  subparser for service-account
    parse_arguments_with(
        [add_config_arguments, spark_user_parser],
        subparsers.add_parser(Actions.CREATE.value, parents=[base_parser]),
    ).add_argument(
        "--primary",
        action="store_true",
        help="Boolean to mark the service account as primary.",
    )

    #  subparser for service-account-cleanup
    parse_arguments_with(
        [spark_user_parser],
        subparsers.add_parser(Actions.DELETE.value, parents=[base_parser]),
    )

    #  subparser for add-config
    parse_arguments_with(
        [add_config_arguments, spark_user_parser],
        subparsers.add_parser(Actions.ADD_CONFIG.value, parents=[base_parser]),
    )

    #  subparser for remove-config
    parse_arguments_with(
        [add_config_arguments, spark_user_parser],
        subparsers.add_parser(Actions.REMOVE_CONFIG.value, parents=[base_parser]),
    )

    #  subparser for sa-conf-get
    parse_arguments_with(
        [spark_user_parser],
        subparsers.add_parser(Actions.GET_CONFIG.value, parents=[base_parser]),
    )

    #  subparser for sa-conf-del
    parse_arguments_with(
        [spark_user_parser],
        subparsers.add_parser(Actions.CLEAR_CONFIG.value, parents=[base_parser]),
    )

    #  subparser for resources-primary-sa
    subparsers.add_parser(Actions.PRIMARY.value, parents=[base_parser])

    #  subparser for list
    subparsers.add_parser(Actions.LIST.value, parents=[base_parser])

    return parser


if __name__ == "__main__":
    args = create_service_account_registry_parser(
        ArgumentParser(description="Spark Client Setup")
    ).parse_args()

    logger = setup_logging(
        args.log_level, args.log_conf_file, "spark8t.cli.service_account_registry"
    )

    kube_interface = get_kube_interface(args)
    context = args.context or kube_interface.context_name

    logger.info(f"Using K8s context: {context}")

    registry = K8sServiceAccountRegistry(kube_interface.with_context(context))

    if args.action == Actions.CREATE:
        service_account = build_service_account_from_args(args)
        service_account.extra_confs = (
            PropertyFile.read(args.properties_file)
            if args.properties_file is not None
            else PropertyFile.empty()
        ) + parse_conf_overrides(args.conf)

        registry.create(service_account)

    elif args.action == Actions.DELETE:
        user_id = build_service_account_from_args(args).id
        logger.info(user_id)
        registry.delete(user_id)

    elif args.action == Actions.ADD_CONFIG:
        input_service_account = build_service_account_from_args(args)

        service_account_in_registry = registry.get(input_service_account.id)

        if service_account_in_registry is None:
            raise NoAccountFound(input_service_account.id)

        account_configuration = (
            service_account_in_registry.configurations
            + (
                PropertyFile.read(args.properties_file)
                if args.properties_file is not None
                else PropertyFile.empty()
            )
            + parse_conf_overrides(args.conf)
        )

        registry.set_configurations(input_service_account.id, account_configuration)

    elif args.action == Actions.REMOVE_CONFIG:
        input_service_account = build_service_account_from_args(args)

        service_account_in_registry = registry.get(input_service_account.id)

        if service_account_in_registry is None:
            raise NoAccountFound(input_service_account.id)

        registry.set_configurations(
            input_service_account.id,
            service_account_in_registry.configurations.remove(args.conf),
        )

    elif args.action == Actions.GET_CONFIG:
        input_service_account = build_service_account_from_args(args)

        maybe_service_account = registry.get(input_service_account.id)

        if maybe_service_account is None:
            raise NoAccountFound(input_service_account.id)

        maybe_service_account.configurations.log(logger.info)

    elif args.action == Actions.CLEAR_CONFIG:
        registry.set_configurations(
            build_service_account_from_args(args).id, PropertyFile.empty()
        )

    elif args.action == Actions.PRIMARY:
        maybe_service_account = registry.get_primary()

        if maybe_service_account is None:
            raise NoAccountFound()

        logger.info(maybe_service_account.id)

    elif args.action == Actions.LIST:
        for service_account in registry.all():
            logger.info(
                str.expandtabs(f"{service_account.id}\t{service_account.primary}")
            )
