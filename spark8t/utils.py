"""Module for general logging functionalities and abstractions."""

import errno
import io
import os
import subprocess
from argparse import ArgumentParser
from contextlib import contextmanager
from copy import deepcopy as copy
from functools import reduce
from logging import Logger, getLogger
from tempfile import NamedTemporaryFile
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Literal,
    Mapping,
    Optional,
    TypedDict,
    TypeVar,
    Union,
)

import yaml

PathLike = Union[str, "os.PathLike[str]"]

LevelTypes = Literal[
    "CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET", 50, 40, 30, 20, 10, 0
]
StrLevelTypes = Literal["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"]

T = TypeVar("T")


class LevelsDict(TypedDict):
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


class WithLogging:
    """Base class to be used for providing a logger embedded in the class."""

    @property
    def logger(self) -> Logger:
        """
        Create logger.
        :return: default logger
        """
        nameLogger = str(self.__class__).replace("<class '", "").replace("'>", "")
        return getLogger(nameLogger)

    def logResult(
        self, msg: Union[Callable[..., str], str], level: StrLevelTypes = "INFO"
    ) -> Callable[..., Any]:
        """
        Return a decorator to allow logging of inputs/outputs.
        :param msg: message to log
        :param level: logging level
        :return: wrapped method
        """

        def wrap(x: Any) -> Any:
            if isinstance(msg, str):
                self.logger.log(levels[level], msg)
            else:
                self.logger.log(levels[level], msg(x))
            return x

        return wrap


def union(*dicts: dict) -> dict:
    """
    Return a dictionary that results from the recursive merge of the input dictionaries.
    :param dicts: list of dicts
    :return: merged dict
    """

    def __dict_merge(dct: dict, merge_dct: dict):
        """
        Recursive dict merge.
        Inspired by :meth:``dict.update()``, instead of updating only top-level keys, dict_merge recurses down into
        dicts nested to an arbitrary depth, updating keys. The ``merge_dct`` is merged into ``dct``.
        :param dct: dict onto which the merge is executed
        :param merge_dct: dct merged into dct
        :return: None
        """
        merged = copy(dct)
        for k, v in merge_dct.items():
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


def _check(value: Optional[T]) -> bool:
    return False if value is None else True


def filter_none(_dict: Dict[T, Any]) -> Dict[T, Any]:
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
    """
    Create a dir, using a formulation consistent between 2.x and 3.x python versions.
    :param path: path to create
    :raises OSError: whenever OSError is raised by makedirs and it's not because the directory exists
    """
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


def create_dir_if_not_exists(directory: PathLike) -> PathLike:
    """
    Create a directory if it does not exist.
    :param directory: path
    :return: directory, str
    """
    if not os.path.exists(directory):
        os.makedirs(directory)
    return directory


def parse_yaml_shell_output(cmd: str) -> Union[Dict[str, Any], str]:
    with io.StringIO() as buffer:
        buffer.write(
            subprocess.check_output(cmd, shell=True, stderr=None).decode("utf-8")
        )
        buffer.seek(0)
        return yaml.safe_load(buffer)


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


def listify(value: Any) -> List[str]:
    return [str(v) for v in value] if isinstance(value, list) else [str(value)]


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
