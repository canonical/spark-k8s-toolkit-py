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
    def spark_user_data(self):
        return self.environ["SPARK_USER_DATA"]

    @property
    def kubectl_cmd(self) -> str:
        """Return default kubectl command."""
        return self.environ.get("SPARK_KUBECTL", "kubectl")

    @property
    def kube_config(self) -> str:
        """Return default kubeconfig to use if not explicitly provided."""
        return self.environ["KUBECONFIG"]

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


