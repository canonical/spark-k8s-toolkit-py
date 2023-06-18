import argparse

import pytest

from spark8t.cli.params import (
    add_config_arguments,
    add_deploy_arguments,
    add_logging_arguments,
    k8s_parser,
    parse_arguments_with,
    spark_user_parser,
)


@pytest.fixture
def shell_parser():
    return parse_arguments_with(
        [
            add_logging_arguments,
            k8s_parser,
            spark_user_parser,
            add_config_arguments,
        ],
        argparse.ArgumentParser(exit_on_error=False),
    )


@pytest.fixture
def submit_parser():
    return parse_arguments_with(
        [
            add_logging_arguments,
            k8s_parser,
            spark_user_parser,
            add_deploy_arguments,
            add_config_arguments,
        ],
        argparse.ArgumentParser(exit_on_error=False),
    )
