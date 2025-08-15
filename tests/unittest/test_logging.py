import logging
import os

import pytest

from spark8t.utils import setup_logging, PropertyFile

TEST_LOGGING_FILE = os.path.join(
    os.path.dirname(__file__), "..", "resources", "logging.yaml"
)


def generate_logs(logger: logging.Logger):
    logger.error("ERROR")
    logger.info("INFO")
    logger.debug("DEBUG")


@pytest.mark.parametrize(
    "log_level, expected_output",
    [("WARN", 1), ("INFO", 2), ("DEBUG", 3)],
)
def test_logging(log_level, expected_output, caplog):
    """
    Test that checks that class loggers inherits the level provided externally
    """
    p = PropertyFile({"k": "v"})

    with caplog.at_level(log_level):
        generate_logs(p.logger)
    assert len(caplog.records) == expected_output


@pytest.mark.parametrize(
    "log_level, expected_level, expected_count",
    [
        ("WARN", logging.WARN, 1),
        ("INFO", logging.INFO, 2),
    ],
)
def test_setup_logging_level(log_level, expected_level, expected_count, caplog):
    """
    Tests that setup_logging provides the expected level to the root logger
    """
    logger = setup_logging(log_level, logger_name="tests")

    assert logger.level == logging.NOTSET
    assert logger.root.level == expected_level

    logger.root.addHandler(caplog.handler)

    with caplog.at_level(log_level):
        generate_logs(logger)
    assert len(caplog.records) == expected_count


@pytest.mark.parametrize(
    "log_level, expected_level",
    [
        ("WARN", logging.WARN),
        ("INFO", logging.INFO),
    ],
)
def test_setup_logging_from_file(log_level, expected_level, caplog):
    """
    Tests that setup_logging configures correctly the logger based on the external file
    """

    logger = setup_logging(
        log_level, config_file=TEST_LOGGING_FILE, logger_name="tests"
    )

    assert logger.level == expected_level
    assert logger.root.level == logging.ERROR
