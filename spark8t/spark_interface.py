"""Interface for spark commands."""

from __future__ import annotations

import os
import socket
from enum import Enum
from typing import Any

from spark8t.domain import (
    Defaults,
    PropertyFile,
    ServiceAccount,
)
from spark8t.kube_interface.base import AbstractKubeInterface
from spark8t.utils import (
    WithLogging,
    environ,
    umask_named_temporary_file,
)


class SparkDeployMode(str, Enum):
    """Spark deployment mode."""

    CLIENT = "client"
    CLUSTER = "cluster"

    def __str__(self) -> str:
        """Define string representation.

        TODO(py310): replace inheritance with StrEnum once we drop py310
        """
        return str.__str__(self)


class SparkInterface(WithLogging):
    """Class for providing interfaces for spark commands."""

    def __init__(
        self,
        service_account: ServiceAccount,
        kube_interface: AbstractKubeInterface,
        defaults: Defaults,
    ):
        """Initialise spark for a given service account.

        Args:
            service_account: spark ServiceAccount to be used for executing spark on k8s
            defaults: Defaults class containing relevant default settings.
        """
        self.service_account = service_account
        self.kube_interface = kube_interface
        self.defaults = defaults

    @staticmethod
    def _read_properties_file(namefile: str | None) -> PropertyFile:
        return (
            PropertyFile.read(namefile)
            if namefile is not None
            else PropertyFile.empty()
        )

    @staticmethod
    def _generate_properties_file_from_arguments(confs: list[str]):
        if not confs:
            return PropertyFile({})

        return PropertyFile(
            dict(
                PropertyFile.parse_property_line(line)
                for line in confs
                if PropertyFile.is_line_parsable(line)
            )
        )

    def spark_submit(
        self,
        deploy_mode: SparkDeployMode,
        confs: list[str],
        cli_property: str | None,
        extra_args: list[str],
    ):
        """Submit a spark job.

        Args:
            deploy_mode: "client" or "cluster" depending where the driver will run, locally or on the k8s cluster
                         respectively
            confs: list of extra configuration provided via command line
            cli_property: property-file path provided via command line
            extra_args: extra arguments provided to the spark submit command
        """
        with umask_named_temporary_file(
            mode="w", prefix="spark-conf-", suffix=".conf"
        ) as t:
            self.logger.debug(f"Spark props available for reference at {t.name}\n")

            (
                self._read_properties_file(self.defaults.static_conf_file)
                + self.service_account.configurations
                + self._read_properties_file(self.defaults.env_conf_file)
                + self._read_properties_file(cli_property)
                + self._generate_properties_file_from_arguments(confs)
            ).write(t.file)

            t.flush()

            submit_args = [
                f"--master k8s://{self.service_account.api_server}",
                f"--deploy-mode {deploy_mode}",
                f"--properties-file {t.name}",
            ] + extra_args

            submit_cmd = f"{self.defaults.spark_submit} {' '.join(submit_args)}"

            self.logger.debug(submit_cmd)

            envs = {}
            if self.kube_interface.kube_config_file:
                envs["KUBECONFIG"] = self.kube_interface.kube_config_file

            with environ(**envs):
                os.system(submit_cmd)

    def spark_shell(
        self, confs: list[str], cli_property: str | None, extra_args: list[str]
    ):
        """Start an interactinve spark shell.

        Args:
            confs: list of extra configuration provided via command line
            cli_property: property-file path provided via command line
            extra_args: extra arguments provided to spark shell
        """
        with umask_named_temporary_file(
            mode="w", prefix="spark-conf-", suffix=".conf"
        ) as t:
            self.logger.debug(f"Spark props available for reference at {t.name}\n")

            conf = (
                self._read_properties_file(self.defaults.static_conf_file)
                + PropertyFile(
                    {
                        "spark.driver.extraJavaOptions": f"-Dscala.shell.histfile={self.defaults.scala_history_file}"
                    }
                )
                + self.service_account.configurations
                + self._read_properties_file(self.defaults.env_conf_file)
                + self._read_properties_file(cli_property)
                + self._generate_properties_file_from_arguments(confs)
            )

            conf = self.prefix_optional_detected_driver_host(conf)

            if "spark.driver.host" not in conf.props:
                raise ValueError(
                    "Please specify spark.driver.host configuration property"
                )

            conf.write(t.file)

            t.flush()

            submit_args = [
                f"--master k8s://{self.service_account.api_server}",
                f"--properties-file {t.name}",
            ] + extra_args

            submit_cmd = f"{self.defaults.spark_shell} {' '.join(submit_args)}"

            self.logger.debug(submit_cmd)

            envs = {}
            if self.kube_interface.kube_config_file:
                envs["KUBECONFIG"] = self.kube_interface.kube_config_file

            with environ(**envs):
                os.system(f"touch {self.defaults.scala_history_file}")
                os.system(submit_cmd)

    def pyspark_shell(
        self, confs: list[str], cli_property: str | None, extra_args: list[str]
    ):
        """Start an interactinve pyspark shell.

        Args:
            confs: list of extra configuration provided via command line
            cli_property: property-file path provided via command line
            extra_args: extra arguments provided to pyspark
        """
        with umask_named_temporary_file(
            mode="w", prefix="spark-conf-", suffix=".conf"
        ) as t:
            self.logger.debug(f"Spark props available for reference at {t.name}\n")

            conf = (
                self._read_properties_file(self.defaults.static_conf_file)
                + self.service_account.configurations
                + self._read_properties_file(self.defaults.env_conf_file)
                + self._read_properties_file(cli_property)
                + self._generate_properties_file_from_arguments(confs)
            )

            conf = self.prefix_optional_detected_driver_host(conf)

            if "spark.driver.host" not in conf.props:
                raise ValueError(
                    "Please specify spark.driver.host configuration property"
                )

            conf.write(t.file)

            t.flush()

            submit_args = [
                f"--master k8s://{self.service_account.api_server}",
                f"--properties-file {t.name}",
            ] + extra_args

            submit_cmd = f"{self.defaults.pyspark} {' '.join(submit_args)}"

            self.logger.debug(submit_cmd)

            envs = {}
            if self.kube_interface.kube_config_file:
                envs["KUBECONFIG"] = self.kube_interface.kube_config_file

            with environ(**envs):
                os.system(submit_cmd)

    def spark_sql(
        self,
        confs: list[str],
        cli_property: str | None,
        extra_args: list[str],
    ):
        """Start an interactive Spark SQL shell.

        Args:
            confs: list of extra configuration provided via command line
            cli_property: property-file path provided via command line
            extra_args: extra arguments provided to pyspark
        """
        with umask_named_temporary_file(
            mode="w", prefix="spark-conf-", suffix=".conf"
        ) as t:
            self.logger.debug(f"Spark props available for reference at {t.name}\n")

            conf = (
                self._read_properties_file(self.defaults.static_conf_file)
                + self.service_account.configurations
                + self._read_properties_file(self.defaults.env_conf_file)
                + self._read_properties_file(cli_property)
                + self._generate_properties_file_from_arguments(confs)
            )

            conf = self.prefix_optional_detected_driver_host(conf)

            if "spark.driver.host" not in conf.props:
                raise ValueError(
                    "Please specify spark.driver.host configuration property"
                )

            conf.write(t.file)

            t.flush()

            submit_args = [
                f"--master k8s://{self.service_account.api_server}",
                f"--properties-file {t.name}",
            ] + extra_args

            submit_cmd = f"{self.defaults.spark_sql} {' '.join(submit_args)}"

            self.logger.debug(submit_cmd)

            envs = {}
            if self.kube_interface.kube_config_file:
                envs["KUBECONFIG"] = self.kube_interface.kube_config_file

            with environ(**envs):
                os.system(submit_cmd)

    def prefix_optional_detected_driver_host(self, conf: PropertyFile):
        """Get prefix for driver host."""
        spark_driver_host = self.detect_host()
        if spark_driver_host:
            return PropertyFile({"spark.driver.host": spark_driver_host}) + conf
        else:
            return conf

    def detect_host(self) -> Any:
        """Detect host from API server."""
        host = None
        port = None
        try:
            host = self.service_account.api_server.split(":")[1].split("/")[-1]
            port = (
                self.service_account.api_server.split(":")[2]
                if len(self.service_account.api_server.split(":")) == 3
                else "433"
            )
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((host, int(port)))
            driver_host = s.getsockname()[0]
            s.close()
            return driver_host
        except Exception:
            self.logger.debug(
                f"Driver host autodetection failed for host={host}, port={port}."
            )
            return None
