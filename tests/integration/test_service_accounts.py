import json
import subprocess
import uuid

import pytest

from spark8t.literals import MANAGED_BY_LABELNAME, SPARK8S_LABEL

VALID_BACKENDS = [
    "kubectl",
    "lightkube",
]

ALLOWED_PERMISSIONS = {
    "pods": ["create", "get", "list", "watch", "delete"],
    "configmaps": ["create", "get", "list", "watch", "delete"],
    "services": ["create", "get", "list", "watch", "delete"],
}


@pytest.fixture
def namespace():
    namespace_name = str(uuid.uuid4())
    create_command = ["kubectl", "create", "namespace", namespace_name]
    subprocess.run(create_command, check=True)
    yield namespace_name
    destroy_command = ["kubectl", "delete", "namespace", namespace_name]
    subprocess.run(destroy_command, check=True)


def run_service_account_registry(*args):
    command = ["python3", "-m", "spark8t.cli.service_account_registry", *args]
    output = subprocess.run(command, check=True, capture_output=True)
    return output.stdout.decode(), output.stderr.decode(), output.returncode


def parameterize(permissions):
    parameters = []
    for resource, actions in permissions.items():
        parameters.extend([(action, resource) for action in actions])
    return parameters


@pytest.fixture(params=VALID_BACKENDS)
def service_account(namespace, request):
    username = str(uuid.uuid4())
    backend = request.param

    # Create the service account
    run_service_account_registry(
        "create", "--username", username, "--namespace", namespace, "--backend", backend
    )
    return username, namespace


@pytest.mark.parametrize("backend", VALID_BACKENDS)
@pytest.mark.parametrize("action, resource", parameterize(ALLOWED_PERMISSIONS))
def test_create_service_account(namespace, backend, action, resource):
    """Test creation of service account using the CLI.

    Verify that the serviceaccount, role and rolebinding resources are created
    with appropriate tags applied to them. Also verify that the RBAC permissions
    for the created serviceaccount.
    """

    username = "bikalpa"
    role_name = f"{username}-role"
    role_binding_name = f"{username}-role-binding"

    # Create the service account
    run_service_account_registry(
        "create", "--username", username, "--namespace", namespace, "--backend", backend
    )

    # Check if service account was created with appropriate labels
    service_account_result = subprocess.run(
        ["kubectl", "get", "serviceaccount", username, "-n", namespace, "-o", "json"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert service_account_result.returncode == 0

    service_account = json.loads(service_account_result.stdout)
    assert service_account is not None
    actual_labels = service_account["metadata"]["labels"]
    expected_labels = {MANAGED_BY_LABELNAME: SPARK8S_LABEL}
    assert actual_labels == expected_labels

    # Check if a role was created with appropriate labels
    role_result = subprocess.run(
        ["kubectl", "get", "role", role_name, "-n", namespace, "-o", "json"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert role_result.returncode == 0

    role = json.loads(role_result.stdout)
    assert role is not None
    actual_labels = role["metadata"]["labels"]
    expected_labels = {MANAGED_BY_LABELNAME: SPARK8S_LABEL}
    assert actual_labels == expected_labels

    # Check if a role binding was created with appropriate labels
    role_binding_result = subprocess.run(
        [
            "kubectl",
            "get",
            "rolebinding",
            role_binding_name,
            "-n",
            namespace,
            "-o",
            "json",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert role_binding_result.returncode == 0

    role_binding = json.loads(role_binding_result.stdout)
    assert role_binding is not None
    actual_labels = role_binding["metadata"]["labels"]
    expected_labels = {MANAGED_BY_LABELNAME: SPARK8S_LABEL}
    assert actual_labels == expected_labels

    # Check for RBAC permissions
    sa_identifier = f"system:serviceaccount:{namespace}:{username}"
    rbac_check = subprocess.run(
        [
            "kubectl",
            "auth",
            "can-i",
            action,
            resource,
            "--namespace",
            namespace,
            "--as",
            sa_identifier,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert rbac_check.returncode == 0
    assert rbac_check.stdout.strip() == "yes"


@pytest.mark.parametrize("backend", VALID_BACKENDS)
@pytest.mark.parametrize("action, resource", parameterize(ALLOWED_PERMISSIONS))
def test_delete_service_account(service_account, backend, action, resource):
    username, namespace = service_account
    role_name = f"{username}-role"
    role_binding_name = f"{username}-role-binding"

    # Delete the service account
    run_service_account_registry(
        "delete", "--username", username, "--namespace", namespace, "--backend", backend
    )

    # Check if service account has been deleted
    service_account_result = subprocess.run(
        ["kubectl", "get", "serviceaccount", username, "-n", namespace, "-o", "json"],
        capture_output=True,
        text=True,
    )
    assert service_account_result.returncode != 0

    # Check if the role corresponding to the service account has also been deleted
    role_result = subprocess.run(
        ["kubectl", "get", "role", role_name, "-n", namespace, "-o", "json"],
        capture_output=True,
        text=True,
    )
    assert role_result.returncode != 0

    # Check if the associated role binding has been deleted
    role_binding_result = subprocess.run(
        [
            "kubectl",
            "get",
            "rolebinding",
            role_binding_name,
            "-n",
            namespace,
            "-o",
            "json",
        ],
        capture_output=True,
        text=True,
    )
    assert role_binding_result.returncode != 0

    # Check for RBAC permissions
    sa_identifier = f"system:serviceaccount:{namespace}:{username}"
    rbac_check = subprocess.run(
        [
            "kubectl",
            "auth",
            "can-i",
            action,
            resource,
            "--namespace",
            namespace,
            "--as",
            sa_identifier,
        ],
        capture_output=True,
        text=True,
    )
    assert rbac_check.returncode != 0
    assert rbac_check.stdout.strip() == "no"


@pytest.mark.parametrize("backend", VALID_BACKENDS)
def test_service_account_get_primary(namespace, backend):
    username = str(uuid.uuid4())

    # Create a new service account with --primary option provided
    run_service_account_registry(
        "create",
        "--username",
        username,
        "--namespace",
        namespace,
        "--backend",
        backend,
        "--primary",
    )

    # Attempt to get primary service account
    stdout, stderr, ret_code = run_service_account_registry(
        "get-primary", "--backend", backend
    )
    assert f"{namespace}:{username}" == stdout.strip()


@pytest.mark.parametrize("backend", VALID_BACKENDS)
def test_service_accounts_listing(namespace, backend):
    usernames = [
        str(uuid.uuid4()),
        str(uuid.uuid4()),
        str(uuid.uuid4()),
    ]

    for username in usernames:
        run_service_account_registry(
            "create",
            "--username",
            username,
            "--namespace",
            namespace,
            "--backend",
            backend,
        )

    # List the service accounts
    stdout, stderr, ret_code = run_service_account_registry(
        "list", "--backend", backend
    )
    actual_output_lines = stdout.split("\n")
    expected_outout_lines = [f"{namespace}:{username}" for username in usernames]

    for line in expected_outout_lines:
        assert line in actual_output_lines


@pytest.mark.parametrize("backend", VALID_BACKENDS)
def test_service_account_get_config(service_account, backend):
    username, namespace = service_account
    stdout, stderr, ret_code = run_service_account_registry(
        "get-config",
        "--username",
        username,
        "--namespace",
        namespace,
        "--backend",
        backend,
    )
    actual_configs = set(stdout.splitlines())
    expected_configs = {
        f"spark.kubernetes.authenticate.driver.serviceAccountName={username}",
        f"spark.kubernetes.namespace={namespace}",
    }
    assert actual_configs == expected_configs


@pytest.mark.parametrize("backend", VALID_BACKENDS)
def test_service_account_add_config(service_account, backend):
    username, namespace = service_account

    stdout, stderr, ret_code = run_service_account_registry(
        "get-config",
        "--username",
        username,
        "--namespace",
        namespace,
        "--backend",
        backend,
    )
    original_configs = set(stdout.splitlines())

    config_to_add = "foo=bar"

    # Add a few new configs
    run_service_account_registry(
        "add-config",
        "--conf",
        config_to_add,
        "--username",
        username,
        "--namespace",
        namespace,
        "--backend",
        backend,
    )

    stdout, stderr, ret_code = run_service_account_registry(
        "get-config",
        "--username",
        username,
        "--namespace",
        namespace,
        "--backend",
        backend,
    )
    updated_configs = set(stdout.splitlines())
    added_configs = updated_configs - original_configs

    assert added_configs == set([config_to_add])


@pytest.mark.parametrize("backend", VALID_BACKENDS)
def test_service_account_remove_config(service_account, backend):
    username, namespace = service_account

    config_to_add = "foo=bar"

    # Add a new configs
    run_service_account_registry(
        "add-config",
        "--conf",
        config_to_add,
        "--username",
        username,
        "--namespace",
        namespace,
        "--backend",
        backend,
    )
    stdout, stderr, ret_code = run_service_account_registry(
        "get-config",
        "--username",
        username,
        "--namespace",
        namespace,
        "--backend",
        backend,
    )
    new_configs = set(stdout.splitlines())
    assert config_to_add in new_configs

    # Now remove the added config
    config_to_remove = "foo"
    stdout, stderr, ret_code = run_service_account_registry(
        "remove-config",
        "--conf",
        config_to_remove,
        "--username",
        username,
        "--namespace",
        namespace,
        "--backend",
        backend,
    )
    new_configs = set(stdout.splitlines())
    assert config_to_add not in new_configs


@pytest.mark.parametrize("backend", VALID_BACKENDS)
def test_service_account_clear_config(service_account, backend):
    username, namespace = service_account

    configs_to_add = ["foo1=bar1", "foo2=bar2", "foo3=bar3"]
    conf_opt_string = []
    for config in configs_to_add:
        conf_opt_string.extend(["--conf", config])

    # Add new configs
    run_service_account_registry(
        "add-config",
        *conf_opt_string,
        "--username",
        username,
        "--namespace",
        namespace,
        "--backend",
        backend,
    )
    stdout, stderr, ret_code = run_service_account_registry(
        "get-config",
        "--username",
        username,
        "--namespace",
        namespace,
        "--backend",
        backend,
    )
    new_configs = set(stdout.splitlines())
    assert all(config in new_configs for config in configs_to_add)

    # Now clear all configs
    stdout, stderr, ret_code = run_service_account_registry(
        "clear-config",
        "--username",
        username,
        "--namespace",
        namespace,
        "--backend",
        backend,
    )
    new_configs = set(stdout.splitlines())
    assert not any(config in new_configs for config in configs_to_add)
