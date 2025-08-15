"""Domain module."""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum

from spark8t.utils import PropertyFile


class Defaults:
    """Class containing all relevant defaults for the application."""

    def __init__(self, environ: dict | None = None):
        """Initialize a Defaults class using the value contained in a dictionary.

        Args:
            environ: dictionary representing the environment. Default uses the os.environ key-value pairs.
        """
        if environ is None:
            environ = dict(os.environ)
        self.environ = environ if environ is not None else {}

    @property
    def spark_home(self):
        """Spark home directory path."""
        return self.environ["SPARK_HOME"]

    @property
    def spark_confs(self):
        """Spark configuration directory path."""
        return self.environ.get("SPARK_CONFS", os.path.join(self.spark_home, "conf"))

    @property
    def kubernetes_api(self):
        """K8s api endpoint."""
        return (
            f"https://{self.environ['KUBERNETES_SERVICE_HOST']}:"
            + f"{self.environ['KUBERNETES_SERVICE_PORT']}"
        )

    @property
    def spark_user_data(self):
        """User data path."""
        return self.environ["SPARK_USER_DATA"]

    @property
    def kubectl_cmd(self) -> str:
        """Return default kubectl command."""
        return self.environ.get("SPARK_KUBECTL", "kubectl")

    @property
    def kube_config(self) -> str | None:
        """Return default kubeconfig to use if provided in env variable."""
        filename = self.environ.get("KUBECONFIG", None)
        return filename if filename else None

    @property
    def static_conf_file(self) -> str:
        """Return static config properties file packaged with the client artefacts."""
        return f"{self.spark_confs}/spark-defaults.conf"

    @property
    def env_conf_file(self) -> str | None:
        """Return env var provided by user to point to the config properties file with conf overrides."""
        return self.environ.get("SPARK_CLIENT_ENV_CONF")

    @property
    def service_account(self):
        """Spark service account."""
        return "spark"

    @property
    def namespace(self):
        """Spark operating namespace."""
        return "defaults"

    @property
    def scala_history_file(self):
        """Scala history file path."""
        return f"{self.spark_user_data}/.scala_history"

    @property
    def spark_submit(self) -> str:
        """spark-submit binary path."""
        return f"{self.spark_home}/bin/spark-submit"

    @property
    def spark_shell(self) -> str:
        """spark-shell binary path."""
        return f"{self.spark_home}/bin/spark-shell"

    @property
    def pyspark(self) -> str:
        """Pyspark binary path."""
        return f"{self.spark_home}/bin/pyspark"

    @property
    def spark_sql(self) -> str:
        """spark-sql binary path."""
        return f"{self.spark_home}/bin/spark-sql"

    @property
    def dir_package(self) -> str:
        """Package directory path."""
        return os.path.dirname(__file__)

    @property
    def template_dir(self) -> str:
        """Template directory path."""
        return f"{self.dir_package}/resources/templates"

    @property
    def template_serviceaccount(self) -> str:
        """Service account template path."""
        return f"{self.template_dir}/serviceaccount_yaml.tmpl"

    @property
    def template_role(self) -> str:
        """Role template path."""
        return f"{self.template_dir}/role_yaml.tmpl"

    @property
    def template_rolebinding(self) -> str:
        """Rolebinding template path."""
        return f"{self.template_dir}/rolebinding_yaml.tmpl"


@dataclass
class ServiceAccount:
    """Class representing the spark ServiceAccount domain object."""

    name: str
    namespace: str
    api_server: str
    primary: bool = False
    extra_confs: PropertyFile = PropertyFile.empty()
    integration_hub_confs: PropertyFile = PropertyFile.empty()

    @property
    def id(self):
        """Return the service account id, as a concatenation of namespace and username."""
        return f"{self.namespace}:{self.name}"

    @property
    def _k8s_configurations(self):
        return PropertyFile(
            {
                "spark.kubernetes.authenticate.driver.serviceAccountName": self.name,
                "spark.kubernetes.namespace": self.namespace,
            }
        )

    @property
    def configurations(self) -> PropertyFile:
        """Return the service account configuration, associated to a given spark service account."""
        return self.integration_hub_confs + self.extra_confs + self._k8s_configurations


class KubernetesResourceType(str, Enum):
    """Kubernetes resource."""

    SERVICEACCOUNT = "serviceaccount"
    ROLE = "role"
    ROLEBINDING = "rolebinding"
    SECRET = "secret"
    SECRET_GENERIC = "secret generic"
    NAMESPACE = "namespace"

    def __str__(self) -> str:
        """Define string representation.

        TODO(py310): replace inheritance with StrEnum once we drop py310
        """
        return str.__str__(self)
