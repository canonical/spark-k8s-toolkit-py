"""Module for general logging functionalities and abstractions."""

import errno
import io
import json
import logging
import os
import subprocess
from contextlib import contextmanager
from copy import deepcopy as copy
from functools import reduce
from logging import Logger, config, getLogger
from tempfile import NamedTemporaryFile
from typing import Any, Callable, Literal, Mapping, TypedDict, TypeVar, TypeAlias
from urllib.parse import quote, unquote

import yaml
from envyaml import EnvYAML

PathLike: TypeAlias = str | os.PathLike[str]

LevelTypes = Literal[
    "CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET", 50, 40, 30, 20, 10, 0
]
StrLevelTypes = Literal["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"]

T = TypeVar("T")


class LevelsDict(TypedDict):
    """Logger levels."""

    CRITICAL: Literal[50]
    ERROR: Literal[40]
    WARNING: Literal[30]
    INFO: Literal[20]
    DEBUG: Literal[10]
    NOTSET: Literal[0]


DEFAULT_LOG_LEVEL: StrLevelTypes = "INFO"

levels: LevelsDict = {
    "CRITICAL": 50,
    "ERROR": 40,
    "WARNING": 30,
    "INFO": 20,
    "DEBUG": 10,
    "NOTSET": 0,
}

DEFAULT_LOGGING_FILE = os.path.join(
    os.path.dirname(__file__), "resources", "logging.yaml"
)


def config_from_json(path_to_file: str = DEFAULT_LOGGING_FILE) -> None:
    """
    Configure logger from json.

    :param path_to_file: path to configuration file

    :type path_to_file: str

    :return: configuration for logger
    """
    with open(path_to_file, "rt") as fid:
        configFile = json.load(fid)
    config.dictConfig(configFile)


def config_from_yaml(path_to_file: str = DEFAULT_LOGGING_FILE) -> None:
    """
    Configure logger from yaml.

    :param path_to_file: path to configuration file

    :type path_to_file: str

    :return: configuration for logger
    """
    config.dictConfig(dict(EnvYAML(path_to_file, strict=False)))


def config_from_file(path_to_file: str = DEFAULT_LOGGING_FILE) -> None:
    """
    Configure logger from file.

    :param path_to_file: path to configuration file

    :type path_to_file: str

    :return: configuration for logger
    """
    readers = {
        ".yml": config_from_yaml,
        ".yaml": config_from_yaml,
        ".json": config_from_json,
    }

    _, file_extension = os.path.splitext(path_to_file)

    if file_extension not in readers.keys():
        raise NotImplementedError(
            f"Reader for file extension {file_extension} is not supported"
        )

    return readers[file_extension](path_to_file)


class WithLogging:
    """Base class to be used for providing a logger embedded in the class."""

    @property
    def logger(self) -> Logger:
        """Create logger.

        :return: default logger.
        """
        nameLogger = str(self.__class__).replace("<class '", "").replace("'>", "")
        return getLogger(nameLogger)

    def logResult(
        self, msg: Callable[..., str] | str, level: StrLevelTypes = "INFO"
    ) -> Callable[..., Any]:
        """Return a decorator to allow logging of inputs/outputs.

        :param msg: message to log
        :param level: logging level
        :return: wrapped method.
        """

        def wrap(x: Any) -> Any:
            if isinstance(msg, str):
                self.logger.log(levels[level], msg)
            else:
                self.logger.log(levels[level], msg(x))
            return x

        return wrap


def setup_logging(
    log_level: str, config_file: str | None = None, logger_name: str | None = None
) -> logging.Logger:
    """Set up logging from configuration file."""
    with environ(LOG_LEVEL=log_level) as _:
        config_from_file(config_file or DEFAULT_LOGGING_FILE)
    return logging.getLogger(logger_name) if logger_name else logging.root


def union(*dicts: dict) -> dict:
    """
    Return a dictionary that results from the recursive merge of the input dictionaries.

    :param dicts: list of dicts
    :return: merged dict.
    """

    def __dict_merge(dct: dict, merge_dct: dict):
        """
        Recursive dict merge.

        Inspired by :meth:``dict.update()``, instead of updating only top-level keys, dict_merge recurses down into
        dicts nested to an arbitrary depth, updating keys. The ``merge_dct`` is merged into ``dct``.
        :param dct: dict onto which the merge is executed
        :param merge_dct: dct merged into dct
        :return: None.
        """
        merged = copy(dct)
        for k, _v in merge_dct.items():
            if (
                k in dct
                and isinstance(dct[k], dict)
                and isinstance(merge_dct[k], Mapping)
            ):
                merged[k] = __dict_merge(dct[k], merge_dct[k])
            else:
                merged[k] = merge_dct[k]
        return merged

    return reduce(__dict_merge, dicts)


def _check(value: Any) -> bool:
    return False if value is None else True


def filter_none(_dict: dict[T, Any]) -> dict[T, Any]:
    """
    Return a dictionary where the key,value pairs are filtered where the value is None.

    :param _dict: dict with Nones
    :return: dict without Nones
    """
    agg = {}
    for k, v in _dict.items():
        if isinstance(v, dict):
            agg[k] = filter_none(v)
        elif _check(v):
            agg[k] = v
    return agg


def umask_named_temporary_file(*args, **kargs):
    """Return a temporary file descriptor readable by all users."""
    file_desc = NamedTemporaryFile(*args, **kargs)
    mask = os.umask(0o666)
    os.umask(mask)
    os.chmod(file_desc.name, 0o666 & ~mask)
    return file_desc


def mkdir(path: PathLike) -> None:
    """Create a dir, using a formulation consistent between 2.x and 3.x python versions.

    :param path: path to create
    :raises OSError: whenever OSError is raised by makedirs and it's not because the directory exists.
    """
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


def create_dir_if_not_exists(directory: PathLike) -> PathLike:
    """Create a directory if it does not exist.

    :param directory: path
    :return: directory, str.
    """
    if not os.path.exists(directory):
        os.makedirs(directory)
    return directory


def parse_yaml_shell_output(cmd: str) -> dict[str, Any] | str:
    """
    Execute command and parse output as YAML.

    Args:
        cmd: string with bash command

    Raises:
        CalledProcessError: when the bash command fails and exits with code other than 0

    Returns:
        dictionary representing the output of the command
    """
    with io.StringIO() as buffer:
        buffer.write(execute_command_output(cmd))
        buffer.seek(0)
        return yaml.safe_load(buffer)


def execute_command_output(cmd: str) -> str:
    """
    Execute command and return the output.

    Args:
        cmd: string with bash command

    Raises:
        CalledProcessError: when the bash command fails and exits with code other than 0

    Returns:
        output of the command
    """
    try:
        output = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT
        ).decode("utf-8")
    except subprocess.CalledProcessError as e:
        raise e

    return output


@contextmanager
def environ(*remove, **update):
    """
    Temporarily updates the ``os.environ`` dictionary in-place.

    The ``os.environ`` dictionary is updated in-place so that the modification
    is sure to work in all situations.

    :param remove: Environment variables to remove.
    :param update: Dictionary of environment variables and values to add/update.
    """
    env = os.environ
    update = update or {}
    remove = remove or []

    # List of environment variables being updated or removed.
    stomped = (set(update.keys()) | set(remove)) & set(env.keys())
    # Environment variables and values to restore on exit.
    update_after = {k: env[k] for k in stomped}
    # Environment variables and values to remove on exit.
    remove_after = frozenset(k for k in update if k not in env)

    try:
        [env.pop(k, None) for k in remove]
        env.update(update)
        yield
    finally:
        [env.pop(k) for k in remove_after]
        env.update(update_after)


def listify(value: Any) -> list[str]:
    """Flatten potentially nested structure."""
    return [str(v) for v in value] if isinstance(value, list) else [str(value)]


class PercentEncodingSerializer:
    """This class provides a way to serialize and de-serialize keys to be stored in k8s.

    Keys in kubernetes need to comply with some format (described by the regex '[-._a-zA-Z0-9]+').
    In order to extend the range of keys that can be stored, we use a serialization based on
    percent encoding, where % is replaced by _. Underscores are still supported but transformed
    into a double underscore
    """

    _SPECIAL = "§"

    def __init__(self, percent_char: str = "_"):
        self.percent_char = percent_char

    @property
    def _double_percent_char(self) -> str:
        return "".join([self.percent_char] * 2)

    def serialize(self, input_string: str) -> str:
        """Serialize percent encoded input."""
        return (
            quote(input_string)
            .replace(self.percent_char, self._double_percent_char)
            .replace("%", self.percent_char)
        )

    def deserialize(self, input_string: str) -> str:
        """Deserialize percent encoded input."""
        return unquote(
            input_string.replace(self._double_percent_char, self._SPECIAL)
            .replace(self.percent_char, "%")
            .replace(self._SPECIAL, self.percent_char)
        )
