"""Package specific exception module."""


class K8sClusterNotReachable(Exception):
    """Kubernetes cluster cannot be reached successfully by the client."""

    def __init__(self, k8s_master: str):
        self.k8s_master = k8s_master


class ResourceNotFound(FileNotFoundError):
    """General Exception representing a general resource not found."""

    def __init__(self, resource_name: str):
        self.resource_name = resource_name


class K8sResourceNotFound(ResourceNotFound):
    """Requested resource in K8s cannot be found."""

    def __init__(self, resource_name: str, resource_type: str):
        super().__init__(resource_name)
        self.resource_type = resource_type


class PrimaryAccountNotFound(ResourceNotFound):
    """Requested primary account cannot be fetched as there exists no account labeled as primary."""

    def __init__(self):
        super().__init__("primary")

    def __str__(self) -> str:
        """Str representation."""
        return "Primary account not found. Please create or tag an account as primary."


class AccountNotFound(ResourceNotFound):
    """Requested Spark account that does not exist."""

    def __init__(self, account: str):
        super().__init__(account)

    @property
    def account(self):
        """Account name."""
        return self.resource_name

    def __str__(self) -> str:
        """Str representation."""
        return f"Account {self.account} could not be found."


class NamespaceNotFound(ResourceNotFound):
    """Requested namespace that does not exist."""

    def __init__(self, namespace: str):
        super().__init__(namespace)

    @property
    def namespace(self):
        """Namespace denomination."""
        return self.resource_name

    def __str__(self) -> str:
        """Str representation."""
        return f"Namespace {self.namespace} could not be found."


class FormatError(SyntaxError):
    """Exception to be used when input provided by the user cannot be parsed."""

    pass


class ResourceAlreadyExists(FileExistsError):
    """The resource already exists in the K8s cluster."""

    pass
