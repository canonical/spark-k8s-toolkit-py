import io
import os
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from spark8t.utils import WithLogging, union


class PropertyFile(WithLogging):
    """Class for providing basic functionalities for IO properties files."""

    def __init__(self, props: Dict[str, Any]):
        """Initialize a PropertyFile class with data provided by a dictionary.

        Args:
            props: input dictionary
        """
        self.props = props

    def __len__(self):
        """Return the size of the property dictionary, i.e. the number of configuration parameters."""
        return len(self.props)

    @staticmethod
    def _is_property_with_options(key: str) -> bool:
        """Check if a given property is known to be options-like requiring special parsing.

        Args:
            key: Property for which special options-like parsing decision has to be taken
        """
        return key in ["spark.driver.extraJavaOptions"]

    @staticmethod
    def is_line_parsable(line: str) -> bool:
        """Check if a given line is parsable(not empty or commented).

        Args:
            line: a line of the configuration
        """
        # empty line
        if len(line.strip()) == 0:
            return False
        # commented line
        elif line.strip().startswith("#"):
            return False
        return True

    @staticmethod
    def parse_property_line(line: str) -> Tuple[str, str]:
        prop_assignment = list(filter(None, re.split("=| ", line.strip())))
        prop_key = prop_assignment[0].strip()
        if PropertyFile._is_property_with_options(prop_key):
            option_assignment = line.split("=", 1)
            value = option_assignment[1].strip()
        else:
            value = prop_assignment[1].strip()
        return prop_key, value

    @classmethod
    def _read_property_file_unsafe(cls, name: str) -> Dict:
        """Read properties in given file into a dictionary.

        Args:
            name: file name to be read
        """
        defaults = dict()
        with open(name) as f:
            for line in f:
                # skip empty or commented line
                if not PropertyFile.is_line_parsable(line):
                    continue
                key, value = cls.parse_property_line(line)
                defaults[key] = os.path.expandvars(value)
        return defaults

    @classmethod
    def read(cls, filename: str) -> "PropertyFile":
        """Read properties file and return a PropertyFile object.

        Args:
            filename: input filename
        """
        try:
            return PropertyFile(cls._read_property_file_unsafe(filename))
        except FileNotFoundError as e:
            raise e

    def write(self, fp: io.TextIOWrapper) -> "PropertyFile":
        """Write out a property file to disk.

        Args:
            fp: file pointer to write to
        """
        for k, v in self.props.items():
            line = f"{k}={v.strip()}"
            fp.write(line + "\n")
        return self

    def log(self, log_func: Optional[Callable[[str], None]] = None) -> "PropertyFile":
        """Print a given dictionary to screen.

        Args:
            log_func: callable to specify another custom printer function. Default uses the class logger with an
                      INFO level.
        """

        printer = (lambda msg: self.logger.info(msg)) if log_func is None else log_func

        for k, v in self.props.items():
            printer(f"{k}={v}")
        return self

    @classmethod
    def _parse_options(cls, options_string: Optional[str]) -> Dict:
        options: Dict[str, str] = dict()

        if not options_string:
            return options

        # cleanup quotes
        line = options_string.strip().replace("'", "").replace('"', "")
        for arg in line.split("-D")[1:]:
            kv = arg.split("=")
            options[kv[0].strip()] = kv[1].strip()

        return options

    @property
    def options(self) -> Dict[str, Dict]:
        """Extract properties which are known to be options-like requiring special parsing."""
        return {
            k: self._parse_options(v)
            for k, v in self.props.items()
            if self._is_property_with_options(k)
        }

    @staticmethod
    def _construct_options_string(options: Dict) -> str:
        result = ""
        for k in options:
            v = options[k]
            result += f" -D{k}={v}"
        return result

    @classmethod
    def empty(cls) -> "PropertyFile":
        """Return an empty property file object."""
        return PropertyFile(dict())

    def __add__(self, other: "PropertyFile"):
        return self.union([other])

    def union(self, others: List["PropertyFile"]) -> "PropertyFile":
        """Merge multiple PropertyFile objects, with right to left priority.

        Args:
            others: List of Property file to be merged.
        """
        all_together = [self] + others

        simple_properties = union(*[prop.props for prop in all_together])
        merged_options = {
            k: self._construct_options_string(v)
            for k, v in union(*[prop.options for prop in all_together]).items()
        }
        return PropertyFile(union(*[simple_properties, merged_options]))

    def remove(self, keys_or_pairs: List[str]) -> "PropertyFile":
        """Remove keys from PropertyFile properties.

        Note that keys may also be in the form k=v. In this case, matching with the value is
        also done before removing the item.

        Args:
            keys_or_pairs: List of keys to be removed from properties.
        """

        keys_to_remove = set()
        for key_or_pair in keys_or_pairs:
            key, *value_list = key_or_pair.split("=")
            value = "=".join(value_list) if value_list else None
            if key in self.props and (not value or self.props[key] == value):
                keys_to_remove.add(key)

        return PropertyFile(
            {key: self.props[key] for key in self.props if key not in keys_to_remove}
            if keys_to_remove
            else self.props
        )


class Defaults:
    """Class containing all relevant defaults for the application."""

    def __init__(self, environ: Dict = dict(os.environ)):
        """Initialize a Defaults class using the value contained in a dictionary

        Args:
            environ: dictionary representing the environment. Default uses the os.environ key-value pairs.
        """

        self.environ = environ if environ is not None else {}

    @property
    def spark_home(self):
        return self.environ["SPARK_HOME"]

    @property
    def spark_confs(self):
        return self.environ.get("SPARK_CONFS", os.path.join(self.spark_home, "conf"))

    @property
    def kubernetes_api(self):
        return (
            f"https://{self.environ['KUBERNETES_SERVICE_HOST']}:"
            + f"{self.environ['KUBERNETES_SERVICE_PORT']}"
        )

    @property
    def spark_user_data(self):
        return self.environ["SPARK_USER_DATA"]

    @property
    def kubectl_cmd(self) -> str:
        """Return default kubectl command."""
        return self.environ.get("SPARK_KUBECTL", "kubectl")

    @property
    def kube_config(self) -> Union[None, str]:
        """Return default kubeconfig to use if provided in env variable."""
        filename = self.environ.get("KUBECONFIG", None)
        return filename if filename else None

    @property
    def static_conf_file(self) -> str:
        """Return static config properties file packaged with the client artefacts."""
        return f"{self.spark_confs}/spark-defaults.conf"

    @property
    def env_conf_file(self) -> Optional[str]:
        """Return env var provided by user to point to the config properties file with conf overrides."""
        return self.environ.get("SPARK_CLIENT_ENV_CONF")

    @property
    def service_account(self):
        return "spark"

    @property
    def namespace(self):
        return "defaults"

    @property
    def scala_history_file(self):
        return f"{self.spark_user_data}/.scala_history"

    @property
    def spark_submit(self) -> str:
        return f"{self.spark_home}/bin/spark-submit"

    @property
    def spark_shell(self) -> str:
        return f"{self.spark_home}/bin/spark-shell"

    @property
    def pyspark(self) -> str:
        return f"{self.spark_home}/bin/pyspark"

    @property
    def spark_sql(self) -> str:
        return f"{self.spark_home}/bin/spark-sql"

    @property
    def dir_package(self) -> str:
        return os.path.dirname(__file__)

    @property
    def template_dir(self) -> str:
        return f"{self.dir_package}/resources/templates"

    @property
    def template_serviceaccount(self) -> str:
        return f"{self.template_dir}/serviceaccount_yaml.tmpl"

    @property
    def template_role(self) -> str:
        return f"{self.template_dir}/role_yaml.tmpl"

    @property
    def template_rolebinding(self) -> str:
        return f"{self.template_dir}/rolebinding_yaml.tmpl"


@dataclass
class ServiceAccount:
    """Class representing the spark ServiceAccount domain object."""

    name: str
    namespace: str
    api_server: str
    primary: bool = False
    extra_confs: PropertyFile = PropertyFile.empty()

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
        return self.extra_confs + self._k8s_configurations


class KubernetesResourceType(str, Enum):
    SERVICEACCOUNT = "serviceaccount"
    ROLE = "role"
    ROLEBINDING = "rolebinding"
    SECRET = "secret"
    SECRET_GENERIC = "secret generic"
    NAMESPACE = "namespace"
