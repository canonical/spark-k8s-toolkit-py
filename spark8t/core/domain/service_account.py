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
