import json
import os
import subprocess
import uuid
from collections import defaultdict
from typing import Generator, MutableMapping

import pytest

from spark8t.domain import KubernetesResourceType, PropertyFile
from spark8t.kube_interface.lightkube import LightKubeInterface
from spark8t.literals import (
    HUB_LABEL,
    MANAGED_BY_LABELNAME,
    SPARK8S_LABEL,
)
from spark8t.utils import umask_named_temporary_file

from .helpers import run_service_account_registry

ALLOWED_PERMISSIONS = {
    "pods": [
        "create",
        "get",
        "list",
        "watch",
        "delete",
        "deletecollection",
        "patch",
        "update",
    ],
    "configmaps": [
        "create",
        "get",
        "list",
        "watch",
        "delete",
        "deletecollection",
        "patch",
        "update",
    ],
    "services": [
        "create",
        "get",
        "list",
        "watch",
        "delete",
        "deletecollection",
        "patch",
        "update",
    ],
}

ALL_ACTIONS = [
    "create",
    "delete",
    "deletecollection",
    "get",
    "list",
    "patch",
    "update",
    "watch",
]

ALLOWED_PERMISSIONS_USER_SECRET = ["get", "patch", "update"]
ALLOWED_PERMISSIONS_HUB_SECRET = ["get"]


@pytest.fixture
def multiple_namespaces_and_service_accounts() -> Generator[
    MutableMapping[str, list[str]], None, None
]:
    result = defaultdict(list)
    for _ in range(3):
        namespace_name = str(uuid.uuid4())
        create_ns_command = ["kubectl", "create", "namespace", namespace_name]
        subprocess.run(create_ns_command, check=True)

        for _ in range(3):
            sa_name = str(uuid.uuid4())
            run_service_account_registry(
                "create", "--username", sa_name, "--namespace", namespace_name
            )
            result[namespace_name].append(sa_name)

    yield result

    for namespace_name in result.keys():
        destroy_command = ["kubectl", "delete", "namespace", namespace_name]
        subprocess.run(destroy_command, check=True)


@pytest.mark.parametrize("primary", [True, False])
def test_create_service_account(namespace: str, primary: bool) -> None:
    """Test creation of service account using the CLI.

    Verify that the serviceaccount, role and rolebinding resources are created
    with appropriate tags applied to them. Also verify that the RBAC permissions
    for the created serviceaccount are intact.
    """

    username = "foobar"
    role_name = f"{username}-role"
    role_binding_name = f"{username}-role-binding"
    secret_name = f"{SPARK8S_LABEL}-sa-conf-{username}"
    hub_secret_name = f"{HUB_LABEL}-{username}"

    create_args = [
        "create",
        "--username",
        username,
        "--namespace",
        namespace,
    ]
    if primary:
        create_args.append("--primary")

    # Create the service account
    run_service_account_registry(*create_args)

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
    labels = service_account["metadata"]["labels"]
    assert labels[MANAGED_BY_LABELNAME] == SPARK8S_LABEL
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
    labels = role["metadata"]["labels"]
    assert labels[MANAGED_BY_LABELNAME] == SPARK8S_LABEL

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
    labels = role_binding["metadata"]["labels"]
    assert labels[MANAGED_BY_LABELNAME] == SPARK8S_LABEL

    # Check secret creation
    secret_result = subprocess.run(
        [
            "kubectl",
            "get",
            "secret",
            secret_name,
            "-n",
            namespace,
            "-o",
            "json",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert secret_result.returncode == 0

    # Check for RBAC permissions
    sa_identifier = f"system:serviceaccount:{namespace}:{username}"
    for resource, actions in ALLOWED_PERMISSIONS.items():
        for action in actions:
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

    # Check for RBAC permissions for named resources

    resource_name_actions = {
        secret_name: ALLOWED_PERMISSIONS_USER_SECRET,
        hub_secret_name: ALLOWED_PERMISSIONS_HUB_SECRET,
    }

    for resource_name, actions in resource_name_actions.items():
        for action in actions:
            rbac_check = subprocess.run(
                [
                    "kubectl",
                    "auth",
                    "can-i",
                    action,
                    f"secret/{resource_name}",
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

        not_allowed_actions = set(ALL_ACTIONS).difference(actions)
        print(not_allowed_actions)
        for action in not_allowed_actions:
            command = [
                "kubectl",
                "auth",
                "can-i",
                action,
                f"secret/{resource_name}",
                "--namespace",
                namespace,
                "--as",
                sa_identifier,
            ]
            print(" ".join(command))
            rbac_check = subprocess.run(
                command,
                capture_output=True,
                text=True,
            )
            print(f"Return code: {rbac_check.returncode}")
            print(f"Return stdout: {rbac_check.stdout.strip()}")
            assert rbac_check.returncode != 0
            assert rbac_check.stdout.strip() == "no"


def test_create_service_account_when_account_already_exists(service_account) -> None:
    """Test creation of service account when a service account having same name already
    exists in the Kubernetes cluster."""
    username, namespace = service_account

    # Create the service account with same username again
    stdout, stderr, ret_code = run_service_account_registry(
        "create",
        "--username",
        username,
        "--namespace",
        namespace,
    )

    assert ret_code != 0
    assert stdout.strip() == (
        f"Could not create the service account. "
        f"A serviceaccount with name '{username}' already exists."
    )


def test_create_service_account_when_namespace_does_not_exist() -> None:
    """Test creation of service account when the namespace does not exist."""
    # Generate random username and namespace names
    username = str(uuid.uuid4())
    namespace = str(uuid.uuid4())

    # Create the service account in a non-existent namespace
    _, _, ret_code = run_service_account_registry(
        "create", "--username", username, "--namespace", namespace
    )

    assert ret_code == 0

    # Check if service account was created
    service_account_result = subprocess.run(
        ["kubectl", "get", "serviceaccount", username, "-n", namespace, "-o", "json"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert service_account_result.returncode == 0

    # delete created service account
    _, _, ret_code = run_service_account_registry(
        "delete", "--username", username, "--namespace", namespace
    )

    assert ret_code == 0

    # delete created namespace
    namespace_result = subprocess.run(
        ["kubectl", "delete", "namespace", namespace],
        check=True,
        capture_output=True,
        text=True,
    )
    assert namespace_result.returncode == 0


def test_delete_service_account(service_account: tuple[str, str]) -> None:
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
        "delete", "--username", username, "--namespace", namespace
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
    for resource, actions in ALLOWED_PERMISSIONS.items():
        for action in actions:
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


def test_delete_service_account_that_does_not_exist(namespace: str) -> None:
    username = str(uuid.uuid4())

    stdout, stderr, ret_code = run_service_account_registry(
        "delete", "--username", username, "--namespace", namespace
    )
    assert ret_code != 0
    assert stdout.strip() == f"Account {username} could not be found."


def test_service_account_get_primary(namespace: str) -> None:
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
        "--primary",
    )

    # Attempt to get primary service account, this should be the same
    # as the one created before
    stdout, _, _ = run_service_account_registry("get-primary")
    assert f"{namespace}:{username}" == stdout.strip()

    # Also ensure that the `list` command lists this account as primary
    stdout, _, _ = run_service_account_registry("list")
    actual_output_lines = [line for line in stdout.split("\n") if line.strip()]
    expected_outout_lines = [f"{namespace}:{username} (Primary)"]
    assert set(actual_output_lines) == set(expected_outout_lines)

    # Now create another account, with --primary set again.
    # This should effectively make the newly created account the primary account
    username2 = str(uuid.uuid4())
    run_service_account_registry(
        "create",
        "--username",
        username2,
        "--namespace",
        namespace,
        "--primary",
    )
    stdout, _, _ = run_service_account_registry("get-primary")
    assert f"{namespace}:{username2}" == stdout.strip()

    # Also ensure that the `list` command lists the new account as primary
    stdout, _, _ = run_service_account_registry("list")
    actual_output_lines = [line for line in stdout.split("\n") if line.strip()]
    expected_outout_lines = [
        f"{namespace}:{username}",
        f"{namespace}:{username2} (Primary)",
    ]
    assert set(actual_output_lines) == set(expected_outout_lines)


def test_service_accounts_listing(namespace: str) -> None:
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
        )

    # List the service accounts
    stdout, _, _ = run_service_account_registry("list")
    actual_output_lines = stdout.split("\n")
    expected_outout_lines = [f"{namespace}:{username}" for username in usernames]

    # Check if the list contains all newly created accounts
    for line in expected_outout_lines:
        assert line in actual_output_lines


def test_service_accounts_listing_multiple_namespaces(
    multiple_namespaces_and_service_accounts: dict[str, list[str]],
) -> None:
    """Test listing of service accounts across multiple namespaces using the CLI."""
    expected_output_lines = []
    for namespace, usernames in multiple_namespaces_and_service_accounts.items():
        expected_output_lines.extend(
            [f"{namespace}:{username}" for username in usernames]
        )

    # List the service accounts
    stdout, _, _ = run_service_account_registry("list")
    actual_output_lines = [line for line in stdout.split("\n") if line.strip()]

    assert set(expected_output_lines) == set(actual_output_lines)


def test_service_account_get_config(
    service_account: tuple[str, str], kubeinterface: LightKubeInterface
) -> None:
    """Test retrieval of service account configs using the CLI.

    Use a fixture that creates temporary service account, then
    verify the set of default configs are set for the newly created
    service account by calling the `get-config` sub-command.
    """
    username, namespace = service_account

    # Get the default configs created with a service account
    stdout, _, _ = run_service_account_registry(
        "get-config",
        "--username",
        username,
        "--namespace",
        namespace,
    )
    actual_configs = set(stdout.splitlines())

    # Check the default config values
    expected_configs = {
        f"spark.kubernetes.authenticate.driver.serviceAccountName={username}",
        f"spark.kubernetes.namespace={namespace}",
    }
    assert actual_configs == expected_configs

    # add integration hub secret for the test service account
    secret_name = f"{HUB_LABEL}-{username}"

    property_file = PropertyFile({"key": "value"})

    with umask_named_temporary_file(
        mode="w",
        prefix="spark-dynamic-conf-k8s-",
        suffix=".conf",
        dir=os.path.expanduser("~"),
    ) as t:
        property_file.write(t.file)

        t.flush()

        kubeinterface.create(
            KubernetesResourceType.SECRET_GENERIC,
            secret_name,
            namespace=namespace,
            dry_run=False,
            **{"from-env-file": str(t.name)},
        )

    assert kubeinterface.exists(
        KubernetesResourceType.SECRET_GENERIC, secret_name, namespace
    )

    # check that integration hub config is there
    # Get the default configs created with a service account
    stdout, _, _ = run_service_account_registry(
        "get-config",
        "--username",
        username,
        "--namespace",
        namespace,
    )
    actual_configs = set(stdout.splitlines())
    expected_configs_hub = {
        f"spark.kubernetes.authenticate.driver.serviceAccountName={username}",
        f"spark.kubernetes.namespace={namespace}",
        "key=value",
    }

    assert actual_configs == expected_configs_hub

    stdout, _, _ = run_service_account_registry(
        "get-config",
        "--username",
        username,
        "--namespace",
        namespace,
        "--ignore-integration-hub",
    )
    actual_configs = set(stdout.splitlines())
    assert actual_configs == expected_configs


def test_service_account_add_config(
    service_account: tuple[str, str], kubeinterface: LightKubeInterface
) -> None:
    """Test addition of service account config using the CLI.
    Use a fixture that creates temporary service account, add new config,
    and then verify whether `get-config` sub-command returns back the newly
    added config.
    """
    username, namespace = service_account

    # Get the default config values, store them temporarily
    stdout, _, _ = run_service_account_registry(
        "get-config",
        "--username",
        username,
        "--namespace",
        namespace,
    )
    original_configs = set(stdout.splitlines())

    # add integration hub secret for the test service account
    secret_name = f"{HUB_LABEL}-{username}"

    property_file = PropertyFile({"key": "value"})

    with umask_named_temporary_file(
        mode="w",
        prefix="spark-dynamic-conf-k8s-",
        suffix=".conf",
        dir=os.path.expanduser("~"),
    ) as t:
        property_file.write(t.file)

        t.flush()

        kubeinterface.create(
            KubernetesResourceType.SECRET_GENERIC,
            secret_name,
            namespace=namespace,
            dry_run=False,
            **{"from-env-file": str(t.name)},
        )

    assert kubeinterface.exists(
        KubernetesResourceType.SECRET_GENERIC, secret_name, namespace
    )

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
    )

    # Get the new config values (the default ones, plus newly added ones)
    stdout, _, _ = run_service_account_registry(
        "get-config",
        "--username",
        username,
        "--namespace",
        namespace,
        "--ignore-integration-hub",
    )
    updated_configs = set(stdout.splitlines())

    # Check if newly added configs are added successfully
    added_configs = updated_configs - original_configs

    assert added_configs == {config_to_add}


def test_service_account_remove_config(
    service_account: tuple[str, str], kubeinterface: LightKubeInterface
) -> None:
    """Test removal of service account config using the CLI.

    Use a fixture that creates temporary service account, add new config,
    verify it being listed by `get-config` sub-command, delete that
    config with `remove-config` sub-command and finally re-verify that the
    config is not present in the output of `get-config` sub-command.
    """
    username, namespace = service_account

    # add integration hub secret for the test service account
    secret_name = f"{HUB_LABEL}-{username}"

    property_file = PropertyFile({"key": "value"})

    with umask_named_temporary_file(
        mode="w",
        prefix="spark-dynamic-conf-k8s-",
        suffix=".conf",
        dir=os.path.expanduser("~"),
    ) as t:
        property_file.write(t.file)

        t.flush()

        kubeinterface.create(
            KubernetesResourceType.SECRET_GENERIC,
            secret_name,
            namespace=namespace,
            dry_run=False,
            **{"from-env-file": str(t.name)},
        )

    assert kubeinterface.exists(
        KubernetesResourceType.SECRET_GENERIC, secret_name, namespace
    )

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
    )

    # Ensure that the added configs have been successfully created
    stdout, _, _ = run_service_account_registry(
        "get-config",
        "--username",
        username,
        "--namespace",
        namespace,
    )
    new_configs = set(stdout.splitlines())
    assert config_to_add in new_configs

    # Now remove the newly added config
    config_to_remove = "foo"
    stdout, _, _ = run_service_account_registry(
        "remove-config",
        "--conf",
        config_to_remove,
        "--username",
        username,
        "--namespace",
        namespace,
    )

    # Ensure the removed configs no longer exist in service account
    new_configs = set(stdout.splitlines())
    assert config_to_add not in new_configs

    # Ensure that the added configs have been successfully created
    stdout, _, _ = run_service_account_registry(
        "get-config",
        "--username",
        username,
        "--namespace",
        namespace,
        "--ignore-integration-hub",
    )
    conf = set(stdout.splitlines())
    assert "key=value" not in conf


def test_service_account_clear_config(service_account: tuple[str, str]) -> None:
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
    )
    stdout, _, _ = run_service_account_registry(
        "get-config",
        "--username",
        username,
        "--namespace",
        namespace,
    )

    # Ensure that all new configs are added successfully.
    new_configs = set(stdout.splitlines())
    assert all(config in new_configs for config in configs_to_add)

    # Now clear all configs
    stdout, _, _ = run_service_account_registry(
        "clear-config",
        "--username",
        username,
        "--namespace",
        namespace,
    )

    # Ensure that none of the custom configs exist now
    new_configs = set(stdout.splitlines())
    assert not any(config in new_configs for config in configs_to_add)


def test_service_account_get_manifest(namespace: str) -> None:
    """Test get-manifest action of the service_account_registry CLI.

    Verify that the command indeed returns a manifest of K8s resources,
    which when applied will create appropriate kubernetes resources for
    the Spark service account to be created.
    """

    username = "manifest-user"
    role_name = f"{username}-role"
    role_binding_name = f"{username}-role-binding"
    secret_name = f"{SPARK8S_LABEL}-sa-conf-{username}"
    hub_secret_name = f"{HUB_LABEL}-{username}"

    create_args = [
        "get-manifest",
        "--username",
        username,
        "--namespace",
        namespace,
    ]

    # Create the service account
    stdout, stderr, retcode = run_service_account_registry(*create_args)
    assert retcode == 0

    # Write the manifest to a temporary file
    with umask_named_temporary_file(
        mode="w+", prefix="manifest-", suffix=".yaml"
    ) as tmp:
        tmp.write(stdout)
        tmp.flush()

        # Now try applying the manifest file
        apply_result = subprocess.run(
            ["kubectl", "apply", "-f", tmp.name],
            check=True,
            capture_output=True,
            text=True,
        )
        assert apply_result.returncode == 0

    # Check if service account was created
    service_account_result = subprocess.run(
        ["kubectl", "get", "serviceaccount", username, "-n", namespace, "-o", "json"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert service_account_result.returncode == 0

    # Check if a role was created
    role_result = subprocess.run(
        ["kubectl", "get", "role", role_name, "-n", namespace, "-o", "json"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert role_result.returncode == 0

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

    # Check secret creation
    secret_result = subprocess.run(
        [
            "kubectl",
            "get",
            "secret",
            secret_name,
            "-n",
            namespace,
            "-o",
            "json",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert secret_result.returncode == 0

    # Check for RBAC permissions
    sa_identifier = f"system:serviceaccount:{namespace}:{username}"
    for resource, actions in ALLOWED_PERMISSIONS.items():
        for action in actions:
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

    # Check for RBAC permissions for named resources
    resource_name_actions = {
        secret_name: ALLOWED_PERMISSIONS_USER_SECRET,
        hub_secret_name: ALLOWED_PERMISSIONS_HUB_SECRET,
    }

    for resource_name, actions in resource_name_actions.items():
        for action in actions:
            rbac_check = subprocess.run(
                [
                    "kubectl",
                    "auth",
                    "can-i",
                    action,
                    f"secret/{resource_name}",
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

        not_allowed_actions = set(ALL_ACTIONS).difference(actions)
        print(not_allowed_actions)
        for action in not_allowed_actions:
            command = [
                "kubectl",
                "auth",
                "can-i",
                action,
                f"secret/{resource_name}",
                "--namespace",
                namespace,
                "--as",
                sa_identifier,
            ]
            print(" ".join(command))
            rbac_check = subprocess.run(
                command,
                capture_output=True,
                text=True,
            )
            print(f"Return code: {rbac_check.returncode}")
            print(f"Return stdout: {rbac_check.stdout.strip()}")
            assert rbac_check.returncode != 0
            assert rbac_check.stdout.strip() == "no"
