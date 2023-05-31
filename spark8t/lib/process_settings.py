from argparse import Namespace

from spark8t.cli import defaults
from spark8t.domain import Defaults
from spark8t.services import AbstractKubeInterface, KubeInterface, LightKube


def get_kube_interface(args: Namespace) -> AbstractKubeInterface:
    return (
        LightKube(args.kubeconfig or defaults.kube_config, defaults)
        if args.backend == "lightkube"
        else KubeInterface(
            args.kubeconfig or defaults.kube_config,
            context_name=args.context,
            kubectl_cmd=Defaults().kubectl_cmd,
        )
    )
