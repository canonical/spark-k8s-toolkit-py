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
    """A temporary K8S namespace gets cleaned up automatically"""
    namespace_name = str(uuid.uuid4())
    create_command = ["kubectl", "create", "namespace", namespace_name]
    subprocess.run(create_command, check=True)
    yield namespace_name
    destroy_command = ["kubectl", "delete", "namespace", namespace_name]
    subprocess.run(destroy_command, check=True)


def run_service_account_registry(*args):
    """Run service_account_registry CLI command with given set of args

    Returns:
        Tuple: A tuple with the content of stdout, stderr and the return code
            obtained when the command is run.
    """
    command = ["python3", "-m", "spark8t.cli.service_account_registry", *args]
    output = subprocess.run(command, check=True, capture_output=True)
    return output.stdout.decode(), output.stderr.decode(), output.returncode


def parameterize(permissions):
    """
    A utility function to parameterize combinations of actions and RBAC permissions.
    """
    parameters = []
    for resource, actions in permissions.items():
        parameters.extend([(action, resource) for action in actions])
    return parameters


@pytest.fixture(params=VALID_BACKENDS)
def service_account(namespace, request):
    """A temporary service account that gets cleaned up automatically."""
    username = str(uuid.uuid4())
    backend = request.param

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
    for the created serviceaccount are intact.
    """

    username = "bikalpa"
    role_name = f"{username}-role"
    role_binding_name = f"{username}-role-binding"

    # Create the service account
    run_service_account_registry(
        "create", "--username", username, "--namespace", namespace, "--backend", backend
    )

    # Check if service account was created
    service_account_result = subprocess.run(
        ["kubectl", "get", "serviceaccount", username, "-n", namespace, "-o", "json"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert service_account_result.returncode == 0

    # Check if service account was labelled correctly
    service_account = json.loads(service_account_result.stdout)
    assert service_account is not None
    actual_labels = service_account["metadata"]["labels"]
    expected_labels = {MANAGED_BY_LABELNAME: SPARK8S_LABEL}
    assert actual_labels == expected_labels

    # Check if a role was created
    role_result = subprocess.run(
        ["kubectl", "get", "role", role_name, "-n", namespace, "-o", "json"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert role_result.returncode == 0

    # Check if the role was labelled correctly
    role = json.loads(role_result.stdout)
    assert role is not None
    actual_labels = role["metadata"]["labels"]
    expected_labels = {MANAGED_BY_LABELNAME: SPARK8S_LABEL}
    assert actual_labels == expected_labels

    # Check if a role binding was created
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

    # Check if the role binding was labelled correctly
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
    """Test deletion of service account using the CLI.

    Verify that the serviceaccount, role and rolebinding resources are deleted
    as well. Also verify that the RBAC permissions for the removed serviceaccount
    no longer work.
    """
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

    # Check if the associated role binding has been deleted as well
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

    # Check for RBAC permissions, these should be invalid now
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
    """Test retrieval of primary service account using the CLI.

    Creates an service account with --primary option provided,
    and then checks whether the same service account is returned
    upon calling `get-primary` sub-command.
    """
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

    # Attempt to get primary service account, this should be the same
    # as the one created before
    stdout, stderr, ret_code = run_service_account_registry(
        "get-primary", "--backend", backend
    )
    assert f"{namespace}:{username}" == stdout.strip()


@pytest.mark.parametrize("backend", VALID_BACKENDS)
def test_service_accounts_listing(namespace, backend):
    """Test listing of service account using the CLI.

    Create a few service accounts using CLI, and then call
    `list` sub-command to see if the newly created service
    accounts are listed.
    """
    # Create a few service accounts
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

    # Check if the list contains all newly created accounts
    for line in expected_outout_lines:
        assert line in actual_output_lines


@pytest.mark.parametrize("backend", VALID_BACKENDS)
def test_service_account_get_config(service_account, backend):
    """Test retrieval of service account configs using the CLI.

    Use a fixture that creates temporary service account, then
    verify the set of default configs are set for the newly created
    service account by calling the `get-config` sub-command.
    """
    username, namespace = service_account

    # Get the default configs created with a service account
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

    # Check the default config values
    expected_configs = {
        f"spark.kubernetes.authenticate.driver.serviceAccountName={username}",
        f"spark.kubernetes.namespace={namespace}",
    }
    assert actual_configs == expected_configs


@pytest.mark.parametrize("backend", VALID_BACKENDS)
def test_service_account_add_config(service_account, backend):
    """Test addition of service account config using the CLI.

    Use a fixture that creates temporary service account, add new config,
    and then verify whether `get-config` sub-command returns back the newly
    added config.
    """
    username, namespace = service_account

    # Get the default config values, store them temporarily
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

    # Get the new config values (the default ones, plus newly added ones)
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

    # Check if newly added configs are added successfully
    added_configs = updated_configs - original_configs

    assert added_configs == set([config_to_add])


@pytest.mark.parametrize("backend", VALID_BACKENDS)
def test_service_account_remove_config(service_account, backend):
    """Test removal of service account config using the CLI.

    Use a fixture that creates temporary service account, add new config,
    verify it being listed by `get-config` sub-command, delete that
    config with `remove-config` sub-command and finally re-verify that the
    config is not present in the output of `get-config` sub-command.
    """
    username, namespace = service_account

    config_to_add = "foo=bar"

    # Add new configs
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

    # Ensure that the added configs have been successfully created
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

    # Now remove the newly added config
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

    # Ensure the removed configs no longer exist in service account
    new_configs = set(stdout.splitlines())
    assert config_to_add not in new_configs


@pytest.mark.parametrize("backend", VALID_BACKENDS)
def test_service_account_clear_config(service_account, backend):
    """Test deletion of all configs for a service account using the CLI.

    Use a fixture that creates temporary service account, add a few configs,
    clear all configs for the service account and then verify that `get-config`
    sub-command no longer lists the cleared configs.
    """
    username, namespace = service_account

    # Create a list of options for a few config values
    configs_to_add = ["foo1=bar1", "foo2=bar2", "foo3=bar3"]
    conf_options = []
    for config in configs_to_add:
        conf_options.extend(["--conf", config])

    # Add new configs
    run_service_account_registry(
        "add-config",
        *conf_options,
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

    # Ensure that all new configs are added successfully.
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

    # Ensure that none of the custom configs exist now
    new_configs = set(stdout.splitlines())
    assert not any(config in new_configs for config in configs_to_add)
