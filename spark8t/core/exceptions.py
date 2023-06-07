class K8sClusterNotReachable(Exception):
    def __init__(self, k8s_master: str):
        self.k8s_master = k8s_master


class NoAccountFound(Exception):
    pass


class FormatError(SyntaxError):
    pass


class NoResourceFound(FileNotFoundError):
    def __init__(self, resource_name: str):
        self.resource_name = resource_name
