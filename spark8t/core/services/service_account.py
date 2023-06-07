class AbstractServiceAccountRegistry(WithLogging, ABC):
    """Abstract class for implementing service that manages spark ServiceAccount resources."""

    @abstractmethod
    def all(self, namespace: Optional[str] = None) -> List["ServiceAccount"]:
        """Return all existing service accounts."""
        pass

    @abstractmethod
    def create(self, service_account: ServiceAccount) -> str:
        """Create a new service account and return ids associated id.

        Args:
            service_account: ServiceAccount to be stored in the registry
        """
        pass

    @abstractmethod
    def set_configurations(self, account_id: str, configurations: PropertyFile) -> str:
        """Set a new service account configuration for the provided service account id.

        Args:
            account_id: account id for which configuration ought to be set
            configurations: PropertyFile representing the new configuration to be stored
        """
        pass

    @abstractmethod
    def delete(self, account_id: str) -> str:
        """Delete the service account associated with the provided id.

        Args:
            account_id: service account id to be deleted
        """
        pass

    @abstractmethod
    def set_primary(self, account_id: str) -> Optional[str]:
        """Set the primary account to the one related to the provided account id.

        Args:
            account_id: account id to be elected as new primary account
        """
        pass

    def get_primary(self) -> Optional[ServiceAccount]:
        """Return the primary service account. None is there is no primary service account."""
        all_accounts = self.all()

        if len(all_accounts) == 0:
            self.logger.warning("There are no service account available.")
            return None

        primary_accounts = [
            account for account in all_accounts if account.primary is True
        ]
        if len(primary_accounts) == 0:
            self.logger.warning("There are no primary service account available.")
            return None

        if len(primary_accounts) > 1:
            self.logger.warning(
                f"More than one account was found: {','.join([account.name for account in primary_accounts])}. "
                f"Choosing the first: {primary_accounts[0].name}. "
                "Note that this may lead to un-expected behaviour if the other primary is chosen"
            )

        return primary_accounts[0]

    @abstractmethod
    def get(self, account_id: str) -> Optional[ServiceAccount]:
        """Return the service account associated with the provided account id. None if no account was found.

        Args:
            account_id: account id to be used for retrieving the service account.
        """
        pass


class K8sServiceAccountRegistry(AbstractServiceAccountRegistry):
    """Class implementing a ServiceAccountRegistry, based on K8s."""

    def __init__(self, kube_interface: AbstractKubeInterface):
        self.kube_interface = kube_interface

    def all(self, namespace: Optional[str] = None) -> List["ServiceAccount"]:
        """Return all existing service accounts."""
        service_accounts = self.kube_interface.get_service_accounts(
            namespace=namespace, labels=[f"{MANAGED_BY_LABELNAME}={SPARK8S_LABEL}"]
        )
        return [
            self._build_service_account_from_raw(raw["metadata"])
            for raw in service_accounts
        ]

    @staticmethod
    def _get_secret_name(name):
        return f"{SPARK8S_LABEL}-sa-conf-{name}"

    def _retrieve_account_configurations(
        self, name: str, namespace: str
    ) -> PropertyFile:
        secret_name = self._get_secret_name(name)

        try:
            secret = self.kube_interface.get_secret(secret_name, namespace=namespace)[
                "data"
            ]
        except Exception:
            return PropertyFile.empty()

        return PropertyFile(secret)

    def _build_service_account_from_raw(self, metadata: Dict[str, Any]):
        name = metadata["name"]
        namespace = metadata["namespace"]
        primary = PRIMARY_LABELNAME in metadata["labels"]

        return ServiceAccount(
            name=name,
            namespace=namespace,
            primary=primary,
            api_server=self.kube_interface.api_server,
            extra_confs=self._retrieve_account_configurations(name, namespace),
        )

    def set_primary(self, account_id: str) -> Optional[str]:
        """Set the primary account to the one related to the provided account id.

        Args:
            account_id: account id to be elected as new primary account
        """

        # Relabeling primary
        primary_account = self.get_primary()

        if primary_account is not None:
            self.kube_interface.remove_label(
                KubernetesResourceType.SERVICEACCOUNT,
                primary_account.name,
                f"{PRIMARY_LABELNAME}",
                primary_account.namespace,
            )
            self.kube_interface.remove_label(
                KubernetesResourceType.ROLEBINDING,
                f"{primary_account.name}-role-binding",
                f"{PRIMARY_LABELNAME}",
                primary_account.namespace,
            )

        service_account = self.get(account_id)

        if service_account is None:
            raise NoAccountFound(account_id)

        self.kube_interface.set_label(
            KubernetesResourceType.SERVICEACCOUNT,
            service_account.name,
            f"{PRIMARY_LABELNAME}=True",
            service_account.namespace,
        )
        self.kube_interface.set_label(
            KubernetesResourceType.ROLEBINDING,
            f"{service_account.name}-role-binding",
            f"{PRIMARY_LABELNAME}=True",
            service_account.namespace,
        )

        return account_id

    def create(self, service_account: ServiceAccount) -> str:
        """Create a new service account and return ids associated id.

        Args:
            service_account: ServiceAccount to be stored in the registry
        """
        rolename = service_account.name + "-role"
        rolebindingname = service_account.name + "-role-binding"

        self.kube_interface.create(
            KubernetesResourceType.SERVICEACCOUNT,
            service_account.name,
            namespace=service_account.namespace,
        )
        self.kube_interface.create(
            KubernetesResourceType.ROLE,
            rolename,
            namespace=service_account.namespace,
            **{
                "resource": ["pods", "configmaps", "services"],
                "verb": ["create", "get", "list", "watch", "delete"],
            },
        )
        self.kube_interface.create(
            KubernetesResourceType.ROLEBINDING,
            rolebindingname,
            namespace=service_account.namespace,
            **{"role": rolename, "serviceaccount": service_account.id},
        )

        self.kube_interface.set_label(
            KubernetesResourceType.SERVICEACCOUNT,
            service_account.name,
            f"{MANAGED_BY_LABELNAME}={SPARK8S_LABEL}",
            namespace=service_account.namespace,
        )
        self.kube_interface.set_label(
            KubernetesResourceType.ROLE,
            rolename,
            f"{MANAGED_BY_LABELNAME}={SPARK8S_LABEL}",
            namespace=service_account.namespace,
        )
        self.kube_interface.set_label(
            KubernetesResourceType.ROLEBINDING,
            rolebindingname,
            f"{MANAGED_BY_LABELNAME}={SPARK8S_LABEL}",
            namespace=service_account.namespace,
        )

        if service_account.primary is True:
            self.set_primary(service_account.id)

        if len(service_account.extra_confs) > 0:
            self.set_configurations(service_account.id, service_account.extra_confs)

        return service_account.id

    def _create_account_configuration(self, service_account: ServiceAccount):
        secret_name = self._get_secret_name(service_account.name)

        try:
            self.kube_interface.delete(
                KubernetesResourceType.SECRET,
                secret_name,
                namespace=service_account.namespace,
            )
        except Exception:
            pass

        with umask_named_temporary_file(
            mode="w", prefix="spark-dynamic-conf-k8s-", suffix=".conf"
        ) as t:
            self.logger.debug(
                f"Spark dynamic props available for reference at {t.name}\n"
            )

            service_account.extra_confs.write(t.file)

            t.flush()

            self.kube_interface.create(
                KubernetesResourceType.SECRET_GENERIC,
                secret_name,
                namespace=service_account.namespace,
                **{"from-env-file": str(t.name)},
            )

    def set_configurations(self, account_id: str, configurations: PropertyFile) -> str:
        """Set a new service account configuration for the provided service account id.

        Args:
            account_id: account id for which configuration ought to be set
            configurations: PropertyFile representing the new configuration to be stored
        """

        namespace, name = account_id.split(":")

        self._create_account_configuration(
            ServiceAccount(
                name=name,
                namespace=namespace,
                api_server=self.kube_interface.api_server,
                extra_confs=configurations,
            )
        )

        return account_id

    def delete(self, account_id: str) -> str:
        """Delete the service account associated with the provided id.

        Args:
            account_id: service account id to be deleted
        """

        namespace, name = account_id.split(":")

        rolename = name + "-role"
        rolebindingname = name + "-role-binding"

        try:
            self.kube_interface.delete(
                KubernetesResourceType.SERVICEACCOUNT, name, namespace=namespace
            )
        except Exception as e:
            self.logger.debug(e)

        try:
            self.kube_interface.delete(
                KubernetesResourceType.ROLE, rolename, namespace=namespace
            )
        except Exception as e:
            self.logger.debug(e)

        try:
            self.kube_interface.delete(
                KubernetesResourceType.ROLEBINDING, rolebindingname, namespace=namespace
            )
        except Exception as e:
            self.logger.debug(e)

        try:
            self.kube_interface.delete(
                KubernetesResourceType.SECRET,
                self._get_secret_name(name),
                namespace=namespace,
            )
        except Exception as e:
            self.logger.debug(e)

        return account_id

    def get(self, account_id: str) -> Optional[ServiceAccount]:
        namespace, username = account_id.split(":")
        service_account_raw = self.kube_interface.get_service_account(
            username, namespace
        )
        return self._build_service_account_from_raw(service_account_raw["metadata"])


class InMemoryAccountRegistry(AbstractServiceAccountRegistry):
    def __init__(self, cache: Dict[str, ServiceAccount]):
        self.cache = cache

        self._consistency_check()

    def _consistency_check(self):
        primaries = [account for account in self.all() if account.primary is True]

        if len(primaries) > 1:
            self.logger.warning(
                "There exists more than one primary in the service account registry."
            )

    def all(self, namespace: Optional[str] = None) -> List["ServiceAccount"]:
        """Return all existing service accounts."""
        return [
            service_account
            for service_account in self.cache.values()
            if namespace is None or namespace == service_account.namespace
        ]

    def create(self, service_account: ServiceAccount) -> str:
        """Create a new service account and return ids associated id.

        Args:
            service_account: ServiceAccount to be stored in the registry
        """

        if (service_account.primary is True) and any(
            [account.primary for account in self.all()]
        ):
            self.logger.info(
                "Primary service account provided. Switching primary account from account"
            )
            for account_id, account in self.cache.items():
                if account.primary is True:
                    self.logger.debug(
                        f"Setting primary of account {account.id} to False"
                    )
                    account.primary = False

        self.cache[service_account.id] = service_account
        return service_account.id

    def delete(self, account_id: str) -> str:
        """Delete the service account associated with the provided id.

        Args:
            account_id: service account id to be deleted
        """
        return self.cache.pop(account_id).id

    def set_primary(self, account_id: str) -> str:
        """Set the primary account to the one related to the provided account id.

        Args:
            account_id: account id to be elected as new primary account
        """
        if account_id not in self.cache.keys():
            raise NoAccountFound(account_id)

        if any([account.primary for account in self.all()]):
            self.logger.info("Switching primary account")
            for account in self.cache.values():
                if account.primary is True:
                    self.logger.debug(
                        f"Setting primary of account {account.id} to False"
                    )
                    account.primary = False

        self.cache[account_id].primary = True
        return account_id

    def set_configurations(self, account_id: str, configurations: PropertyFile) -> str:
        """Set a new service account configuration for the provided service account id.

        Args:
            account_id: account id for which configuration ought to be set
            configurations: PropertyFile representing the new configuration to be stored
        """

        if account_id not in self.cache.keys():
            raise NoAccountFound(account_id)

        self.cache[account_id].extra_confs = configurations
        return account_id

    def get(self, account_id: str) -> Optional[ServiceAccount]:
        return self.cache[account_id]


