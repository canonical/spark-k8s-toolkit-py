microk8s status --wait-ready
export KUBECONFIG=~/.kube/config
microk8s config | tee $KUBECONFIG
microk8s.enable dns
microk8s.enable rbac
