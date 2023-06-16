class K8sClusterNotReachable(Exception):
    def __init__(self, k8s_master: str):
        self.k8s_master = k8s_master


class ResourceNotFound(FileNotFoundError):
    def __init__(self, resource_name: str):
        self.resource_name = resource_name


class K8sResourceNotFound(ResourceNotFound):
    def __init__(self, resource_name: str, resource_type: str):
        super().__init__(resource_name)
        self.resource_type = resource_type


class PrimaryAccountNotFound(ResourceNotFound):
    def __init__(self):
        super().__init__("primary")

    def __str__(self) -> str:
        return "Primary account not found"


class AccountNotFound(ResourceNotFound):
    def __init__(self, account: str):
        super().__init__(account)

    @property
    def account(self):
        return self.resource_name

    def __str__(self) -> str:
        return f"Account {self.account} not found"


class FormatError(SyntaxError):
    pass
