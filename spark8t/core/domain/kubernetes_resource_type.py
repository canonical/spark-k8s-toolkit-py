class KubernetesResourceType(str, Enum):
    SERVICEACCOUNT = "serviceaccount"
    ROLE = "role"
    ROLEBINDING = "rolebinding"
    SECRET = "secret"
    SECRET_GENERIC = "secret generic"
    NAMESPACE = "namespace"
