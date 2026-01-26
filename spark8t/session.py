#!/usr/bin/env python3
# Copyright 2026 Canonical Limited
# See LICENSE file for licensing details.

"""Spark session module."""

import os
import socket
from urllib.parse import urlparse

import pyspark
from lightkube import Client
from lightkube.core.exceptions import ApiError

from spark8t.kube_interface.lightkube import LightKubeInterface as LightKube
from spark8t.registry.k8s import K8sServiceAccountRegistry
from spark8t.utils import environ


class SparkSession:
    """A context manager for Spark sessions.

    The spark session is created when entering the context and stopped when exiting. The spark session is
    created using the given namespace and service account, if provided. If not, they are inferred from the
    environment variables SPARK_NAMESPACE and SPARK_USERNAME.

    If neither are provided, a ValueError is raised.
    """

    def __init__(
        self, app_name: str, namespace: str | None = None, username: str | None = None
    ):
        self.app_name = app_name
        self.session = None

        if namespace is not None:
            self.namespace = namespace
        elif "SPARK_NAMESPACE" in os.environ:
            self.namespace = os.environ["SPARK_NAMESPACE"]
        else:
            raise ValueError(
                "Namespace must be provided either as argument or via SPARK_NAMESPACE env variable."
            )

        if username is not None:
            self.username = username
        elif "SPARK_USERNAME" in os.environ:
            self.username = os.environ["SPARK_USERNAME"]
        else:
            raise ValueError(
                "Username must be provided either as argument or via SPARK_USERNAME env variable."
            )

    @property
    def _pod_ip(
        self,
    ):
        """Return the driver pod IP address."""
        return socket.gethostbyname(socket.gethostname())

    @property
    def _sa_props(
        self,
    ):
        """Return the spark properties defined in the service account."""
        interface = LightKube(None, None)
        registry = K8sServiceAccountRegistry(interface)

        NO_PROXY = (
            os.environ.get("NO_PROXY", "") + f",{self._k8s_master_hostname}"
            if os.environ.get("NO_PROXY")
            else self._k8s_master_hostname
        )
        no_proxy = (
            os.environ.get("no_proxy", "") + f",{self._k8s_master_hostname}"
            if os.environ.get("no_proxy")
            else self._k8s_master_hostname
        )

        try:
            with environ(NO_PROXY=NO_PROXY, no_proxy=no_proxy):
                service_account = registry.get(f"{self.namespace}:{self.username}")
                return service_account.configurations.props
        except (ApiError, AttributeError):
            return {}

    @property
    def _extra_props(
        self,
    ) -> dict:
        """Return extra spark properties required for k8s communication."""
        return {"spark.driver.host": self._pod_ip}

    @property
    def _k8s_master(
        self,
    ) -> str:
        """Return the k8s api server endpoint."""
        return Client().config.cluster.server

    @property
    def _k8s_master_hostname(
        self,
    ) -> str:
        """Return the k8s api server IP address."""
        return urlparse(self._k8s_master).hostname or ""

    @property
    def config(
        self,
    ) -> dict:
        """Return the complete spark configuration dictionary."""
        return self._sa_props | self._extra_props

    def __enter__(
        self,
    ):
        """Enter the context manager, creating the spark session."""
        if self.session is not None:
            return self.session

        builder = pyspark.sql.SparkSession.builder.appName(self.app_name).master(
            f"k8s://{self._k8s_master}"
        )

        for conf, val in self.config.items():
            builder = builder.config(conf, val)
        self.session = builder.getOrCreate()
        return self.session

    def __exit__(self, *args, **kwargs):
        """Exit the context manager, stopping the spark session."""
        if self.session is not None:
            self.session.stop()
