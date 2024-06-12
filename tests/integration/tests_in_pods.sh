#!/bin/bash

# This file is used to test the spark8t library within a K8s cluster.
# Only the functionalities related to the handling of service accounts can
# be tested, since spark-submit, pyspark and spark-shell would require
# the spark binaries.

setup_env() {
  NAMESPACES=$*

  for NAMESPACE in $NAMESPACES; do
    kubectl create namespace ${NAMESPACE}
  done

  poetry install
}

create_service_account(){

  USERNAME=$1
  NAMESPACE=$2

  poetry run python -m spark8t.cli.service_account_registry create \
    --username $USERNAME --namespace $NAMESPACE
}

setup_test_pod() {
  NAMESPACE=$1
  USERNAME= $2

  yq ea ".spec.serviceAccountName = \"${USERNAME}\"" \
    ./tests/resources/pod.yaml | \
    kubectl -n $NAMESPACE apply -f -

  SLEEP_TIME=1
  for i in {1..5}
  do
    pod_status=$(kubectl -n $NAMESPACE get pod testpod| awk '{ print $3 }' | tail -n 1)
    echo $pod_status
    if [[ "${pod_status}" == "Running" ]]
    then
        echo "testpod is Running now!"
        break
    elif [[ "${i}" -le "5" ]]
    then
        echo "Waiting for the pod to come online..."
        sleep $SLEEP_TIME
    else
        echo "testpod did not come up. Test Failed!"
        exit 3
    fi
    SLEEP_TIME=$(expr $SLEEP_TIME \* 2);
  done

  poetry build

  # Install spark8t
  TARBALL=$(find dist -name "*.tar.gz" | tail -n1)
  kubectl -n $NAMESPACE cp "${TARBALL}" testpod:/home/.
  kubectl -n $NAMESPACE exec testpod -- /bin/bash -c "pip install /home/${TARBALL##*/}"

  # Install kubectl
  VERSION=$(curl -L -s https://dl.k8s.io/release/stable.txt)
  kubectl -n $NAMESPACE exec testpod -- curl -LO "https://dl.k8s.io/release/${VERSION}/bin/linux/amd64/kubectl"
  kubectl -n $NAMESPACE exec testpod -- mv kubectl /usr/local/bin
  kubectl -n $NAMESPACE exec testpod -- chmod +x /usr/local/bin/kubectl
}

check_service_accounts_in_pod() {

  CMD=$1
  CHECK=$2
  EXPECTED_RESULT=$3

  NAMESPACE=$(kubectl get pod --field-selector metadata.name=testpod -A | cut -d " " -f1 | tail -n1)

  echo -e "$(kubectl -n $NAMESPACE exec testpod -- env CMD="$CMD" /bin/bash -c 'python -m spark8t.cli.service_account_registry $CMD')" > spark8t.out

  out=$(/bin/bash -c "cat spark8t.out | $CHECK")
  if [ "${out}" != "${EXPECTED_RESULT}" ]; then
      echo "ERROR: Expected value does not match"
      exit 1
  fi
}

check_service_accounts_admin() {

  CMD=$1
  CHECK=$2
  EXPECTED_RESULT=$3

  poetry run python -m spark8t.cli.service_account_registry $CMD > spark8t.out

  out=$(cat spark8t.out | $CHECK)
 
  if [ "${out}" != "${EXPECTED_RESULT}" ]; then
      echo "ERROR:  Expected value does not match"
      exit 1
  fi
}

cleanup_user() {
  EXIT_CODE=$1
  shift
  NAMESPACES=$*

  for NAMESPACE in $NAMESPACES; do
    kubectl delete namespace ${NAMESPACE}
  done

  if [ "${EXIT_CODE}" -ne "0" ]; then
      exit 1
  fi
}

cleanup_success() {
  echo "cleanup_success()......"
  cleanup_user 0 $*
}

cleanup_failure() {
  echo "cleanup_failure()......"
  cleanup_user 1 $*
}

# Test listing spark accounts in a pod with restricted visibility
( \
  setup_env test test-2 && \
  create_service_account spark test && \
  create_service_account spark test-2 && \
  check_service_accounts_admin "list --backend lightkube" "wc -l" "2" && \
  check_service_accounts_admin "list --backend kubectl" "wc -l" "2" && \
  setup_test_pod test spark && \
  check_service_accounts_in_pod "list --backend lightkube" "wc -l" "1" && \
  check_service_accounts_in_pod "list --backend kubectl" "wc -l" "1" && \
  cleanup_success test test-2 \
) || cleanup_failure test test-2

# Test get-config for spark accounts in a pod with restricted visibility
( \
  setup_env test && \
  create_service_account spark test && \
  setup_test_pod test spark && \
  check_service_accounts_in_pod "get-config --username spark --namespace test --backend lightkube" "grep spark.kubernetes | wc -l" "2" && \
  check_service_accounts_in_pod "get-config --username spark --namespace test --backend kubectl" "grep spark.kubernetes | wc -l" "2" && \
  cleanup_success test  \
) || cleanup_failure test

# Test create spark account on a namespace that does not exist

( \
  kubectl create namespace test-namespace && \
  kubectl apply -f ./tests/resources/namespace-exp.yaml && \
  setup_test_pod test-namespace user1 && \
  check_service_accounts_in_pod "create --username=u1 --namespace=abc --backend lightkube" "grep Namespace" "Namespace abc can not be created." && \
  check_service_accounts_in_pod "create --username=u1 --namespace=abc --backend kubectl" "grep Namespace" "Namespace abc can not be created." && \
  kubectl delete -f ./tests/resources/namespace-exp.yaml && \
  cleanup_success test-namespace \
) || cleanup_failure test-namespace
