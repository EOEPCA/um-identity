import json
import logging
from keycloak import KeycloakOpenIDConnection, KeycloakAdmin, KeycloakUMA, urls_patterns
from keycloak.exceptions import raise_error_from_response, KeycloakGetError, KeycloakPostError, KeycloakPutError

logger = logging.getLogger('um-identity-service')

class KeycloakClient:

    def __init__(self, server_url, realm, username, password):
        self.server_url = server_url
        self.realm = realm
        openid_connection = KeycloakOpenIDConnection(
            server_url=self.server_url,
            username=username,
            password=password,
            verify=self.server_url.startswith('https'),
            timeout=10)
        self.keycloak_admin = KeycloakAdmin(connection=openid_connection)
        self.keycloak_uma = KeycloakUMA(connection=openid_connection)
        self.set_realm(realm)
        admin_client_id = self.keycloak_admin.get_client_id('admin-cli')
        admin_client = self.keycloak_admin.get_client(admin_client_id)
        openid_connection = KeycloakOpenIDConnection(
            server_url=self.server_url,
            user_realm_name="master",
            realm_name=self.realm,
            username=self.keycloak_admin.username,
            password=self.keycloak_admin.password,
            client_id=admin_client.get('clientId'),
            verify=self.server_url.startswith('https'),
            timeout=10)
        self.keycloak_admin = KeycloakAdmin(connection=openid_connection)
        self.keycloak_uma = KeycloakUMA(connection=openid_connection)

    def set_realm(self, realm, skip_exists=True):
        if realm != 'master':
            self.keycloak_admin.create_realm(payload={"realm": self.realm, "enabled": True}, skip_exists=skip_exists)
        self.keycloak_admin.realm_name = self.realm
        self.keycloak_uma.realm_name = self.realm

    def import_realm(self, realm: dict) -> dict:
        return self.keycloak_admin.import_realm(realm)

    def register_resources(self, client_id, resources, skip_exists=False):
        if not isinstance(resources, list):
            resources = [resources]
        response = []
        for resource in resources:
            r = self.register_resource(client_id, resource, skip_exists)
            response.append(r)
        return response

    def register_resource(self, client_id, resource, skip_exists=False):
        _client_id = self.keycloak_admin.get_client_id(client_id)
        response = self.keycloak_admin.create_client_authz_resource(client_id=_client_id, payload=resource, skip_exists=skip_exists)
        logger.info('Created resource:\n' + json.dumps(resource, indent=2))
        logger.info('Response: ' + str(response))
        return response

    def update_resource(self, client_id, resource_id, resource):
        _client_id = self.keycloak_admin.get_client_id(client_id)
        if "_id" not in resource:
            resource["_id"] = resource_id
        elif resource["_id"] != resource_id:
            raise KeycloakGetError(
                error_message="Resource ids on path and body don't matc", response_code=400, response_body=bytearray()
            )
        params_path = {"realm-name": self.realm, "id": _client_id}
        url = urls_patterns.URL_ADMIN_CLIENT_AUTHZ + "/resource/" + resource_id
        data_raw = self.keycloak_admin.connection.raw_put(url.format(**params_path), data=json.dumps(resource))
        return raise_error_from_response(data_raw, KeycloakPutError, expected_codes=[204])

    def delete_resource(self, resource_id, client_id):
        _client_id = self.keycloak_admin.get_client_id(client_id)
        params_path = {"realm-name": self.realm, "id": _client_id}
        url = urls_patterns.URL_ADMIN_CLIENT_AUTHZ + "/resource/" + resource_id
        data_raw = self.keycloak_admin.connection.raw_delete(url.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakPutError)

    def delete_policies(self, client_id, policies):
        if not isinstance(policies, list):
            policies = [policies]
            logger.info("Deleting policies: " + str(policies))
        _client_id = self.keycloak_admin.get_client_id(client_id)
        delete_policies = list(
            filter(lambda p: p.get('name') in policies, self.keycloak_admin.get_client_authz_policies(_client_id)))
        logger.info("Policies to delete: " + str(delete_policies))
        if not delete_policies:
            logger.info("Policies not found: " + str(policies))
            return
        for d in delete_policies:
            self.keycloak_admin.delete_client_authz_policy(client_id=_client_id, policy_id=d.get('id'))

    def register_aggregated_policy(self, client_id, policy, skip_exists=False):
        policy_type = "aggregate"
        _client_id = self.keycloak_admin.get_client_id(client_id)
        params_path = {"realm-name": self.realm, "id": _client_id}
        url = urls_patterns.URL_ADMIN_CLIENT_AUTHZ + "/policy/" + policy_type + "?max=-1"
        data_raw = self.keycloak_admin.raw_post(url.format(**params_path), data=json.dumps(policy))
        return raise_error_from_response(
            data_raw, KeycloakPostError, expected_codes=[201, 409], skip_exists=skip_exists
        )

    def register_client_policy(self, client_id, policy, skip_exists=False):
        policy_type = "client"
        _client_id = self.keycloak_admin.get_client_id(client_id)
        policy["clients"] = [client_id]
        params_path = {"realm-name": self.realm, "id": _client_id}
        url = urls_patterns.URL_ADMIN_CLIENT_AUTHZ + "/policy/" + policy_type + "?max=-1"
        data_raw = self.keycloak_admin.raw_post(url.format(**params_path), data=json.dumps(policy))
        return raise_error_from_response(
            data_raw, KeycloakPostError, expected_codes=[201, 409], skip_exists=skip_exists
        )

    def register_client_scope_policy(self, client_id, policy, skip_exists=False):
        policy_type = "client-scope"
        _client_id = self.keycloak_admin.get_client_id(client_id)
        policy["owner"] = client_id
        params_path = {"realm-name": self.realm, "id": _client_id}
        url = urls_patterns.URL_ADMIN_CLIENT_AUTHZ + "/policy/" + policy_type + "?max=-1"
        data_raw = self.keycloak_admin.raw_post(url.format(**params_path), data=json.dumps(policy))
        return raise_error_from_response(
            data_raw, KeycloakPostError, expected_codes=[201, 409], skip_exists=skip_exists
        )

    def register_group_policy(self, client_id, policy, skip_exists=False):
        policy_type = "group"
        _client_id = self.keycloak_admin.get_client_id(client_id)
        params_path = {"realm-name": self.realm, "id": _client_id}
        url = urls_patterns.URL_ADMIN_CLIENT_AUTHZ + "/policy/" + policy_type + "?max=-1"
        data_raw = self.keycloak_admin.raw_post(url.format(**params_path), data=json.dumps(policy))
        return raise_error_from_response(
            data_raw, KeycloakPostError, expected_codes=[201, 409], skip_exists=skip_exists
        )

    def register_regex_policy(self, client_id, policy, skip_exists=False):
        policy_type = "regex"
        _client_id = self.keycloak_admin.get_client_id(client_id)
        params_path = {"realm-name": self.realm, "id": _client_id}
        url = urls_patterns.URL_ADMIN_CLIENT_AUTHZ + "/policy/" + policy_type + "?max=-1"
        data_raw = self.keycloak_admin.raw_post(url.format(**params_path), data=json.dumps(policy))
        return raise_error_from_response(
            data_raw, KeycloakPostError, expected_codes=[201, 409], skip_exists=skip_exists
        )

    def register_role_policy(self, client_id, policy, skip_exists=False):
        policy_type = "role"
        if not isinstance(policy["roles"], list):
            policy["roles"] = [policy["roles"]]
        _client_id = self.keycloak_admin.get_client_id(client_id)
        params_path = {"realm-name": self.realm, "id": _client_id}
        url = urls_patterns.URL_ADMIN_CLIENT_AUTHZ + "/policy/" + policy_type + "?max=-1"
        data_raw = self.keycloak_admin.raw_post(url.format(**params_path), data=json.dumps(policy))
        return raise_error_from_response(
            data_raw, KeycloakPostError, expected_codes=[201, 409], skip_exists=skip_exists
        )

    def register_time_policy(self, client_id, policy, skip_exists=False):
        # time can be one of:
        # "notAfter":"1970-01-01 00:00:00"
        # "notBefore":"1970-01-01 00:00:00"
        # "dayMonth":<day-of-month>
        # "dayMonthEnd":<day-of-month>
        # "month":<month>
        # "monthEnd":<month>
        # "year":<year>
        # "yearEnd":<year>
        # "hour":<hour>
        # "hourEnd":<hour>
        # "minute":<minute>
        # "minuteEnd":<minute>
        policy_type = "time"
        _client_id = self.keycloak_admin.get_client_id(client_id)
        params_path = {"realm-name": self.realm, "id": _client_id}
        url = urls_patterns.URL_ADMIN_CLIENT_AUTHZ + "/policy/" + policy_type + "?max=-1"
        data_raw = self.keycloak_admin.raw_post(url.format(**params_path), data=json.dumps(policy))
        return raise_error_from_response(
            data_raw, KeycloakPostError, expected_codes=[201, 409], skip_exists=skip_exists
        )

    def register_user_policy(self, client_id, policy, skip_exists=False):
        if not isinstance(policy['users'], list):
            policy['users'] = [policy['users']]
        policy_type = "user"
        _client_id = self.keycloak_admin.get_client_id(client_id)
        params_path = {"realm-name": self.realm, "id": _client_id}
        url = urls_patterns.URL_ADMIN_CLIENT_AUTHZ + "/policy/" + policy_type + "?max=-1"
        data_raw = self.keycloak_admin.raw_post(url.format(**params_path), data=json.dumps(policy))
        return raise_error_from_response(
            data_raw, KeycloakPostError, expected_codes=[201, 409], skip_exists=skip_exists
        )

    def register_general_policy(self, policy, client_id, policy_type, skip_exists=False):
        _client_id = self.keycloak_admin.get_client_id(client_id)
        params_path = {"realm-name": self.realm, "id": _client_id}
        url = urls_patterns.URL_ADMIN_CLIENT_AUTHZ + "/policy/" + policy_type + "?max=-1"
        data_raw = self.keycloak_admin.raw_post(url.format(**params_path), data=json.dumps(policy))
        return raise_error_from_response(
            data_raw, KeycloakPostError, expected_codes=[201, 409], skip_exists=skip_exists
        )

    def assign_resources_permissions(self, client_id, permissions, skip_exists=False):
        if not isinstance(permissions, list):
            permissions = [permissions]
        _client_id = self.keycloak_admin.get_client_id(client_id)
        response = []
        for permission in permissions:
            r = self.keycloak_admin.create_client_authz_resource_based_permission(client_id=_client_id,
                                                                                         payload=permission,
                                                                                         skip_exists=skip_exists)
            logger.info("Creating resource permission: " + json.dumps(permission, indent=2))
            logger.info("Response: " + str(r))
            response.append(r)
        return response

    def create_user(self, username, password, realm_roles=None, exist_ok=True) -> str:
        if realm_roles is None:
            realm_roles = []
        if not isinstance(realm_roles, list):
            realm_roles = [realm_roles]
        payload = {
            "username": username,
            "enabled": True
        }
        logger.info('Registering user: ' + json.dumps(payload, indent=2))
        user_id = self.keycloak_admin.create_user(payload, exist_ok=exist_ok)
        logger.info('Created user: ' + str(user_id))
        logger.info("Changing password for user: " + str(user_id))
        self.keycloak_admin.set_user_password(user_id, password, temporary=False)
        if realm_roles:
            self.assign_realm_roles_to_user(user_id, realm_roles)
        return user_id

    def get_user_token(self, username, password):
        """Gets a user token using username/password authentication.
        """
        return self.keycloak_admin.connection.keycloak_openid.token(username, password, scope="openid profile")

    def get_resources(self, client_id):
        _client_id = self.keycloak_admin.get_client_id(client_id)
        return self.keycloak_admin.get_client_authz_resources(_client_id)

    def get_resource_id(self, name: str = "",
                        exact_name: bool = False,
                        uri: str = "",
                        owner: str = "",
                        resource_type: str = "",
                        scope: str = "",
                        first: int = 0,
                        maximum: int = -1, ) -> [str]:
        """Gets a resource id from attributes
        """
        return self.keycloak_uma.resource_set_list_ids(name=name, exact_name=exact_name, uri=uri, owner=owner,
                                                       resource_type=resource_type, scope=scope, first=first,
                                                       maximum=maximum)

    def __query_resources(self, name: str = "",
                          exact_name: bool = False,
                          uri: str = "",
                          owner: str = "",
                          resource_type: str = "",
                          scope: str = "",
                          first: int = 0,
                          maximum: int = -1) -> list[str]:
        """Query for list of resource set ids.

        Spec
        https://docs.kantarainitiative.org/uma/rec-oauth-resource-reg-v1_0_1.html#list-resource-sets

        :param name: query resource name
        :type name: str
        :param exact_name: query exact match for resource name
        :type exact_name: bool
        :param uri: query resource uri
        :type uri: str
        :param owner: query resource owner
        :type owner: str
        :param resource_type: query resource type
        :type resource_type: str
        :param scope: query resource scope
        :type scope: str
        :param first: index of first matching resource to return
        :type first: int
        :param maximum: maximum number of resources to return (-1 for all)
        :type maximum: int
        :return: List of ids
        :rtype: List[str]
        """
        query = dict()
        if name:
            query["name"] = name
            if exact_name:
                query["exactName"] = "true"
        if uri:
            query["uri"] = uri
        if owner:
            query["owner"] = owner
        if resource_type:
            query["type"] = resource_type
        if scope:
            query["scope"] = scope
        if first > 0:
            query["first"] = first
        if maximum >= 0:
            query["max"] = maximum
        query["deep"] = True

        data_raw = self.keycloak_uma.connection.raw_get(
            self.keycloak_uma.uma_well_known["resource_registration_endpoint"], **query
        )
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[200])

    def get_resource(self, resource_id: str):
        return self.keycloak_uma.resource_set_read(resource_id)

    def get_permission_ticket(self, resources: list[str]):
        if not isinstance(resources, list):
            resources = [resources]
        payload = [
            {"resource_id": resource} for resource in resources
        ]
        data = self.keycloak_uma.connection.raw_post(
            f"${self.keycloak_uma.connection.base_url}realms/{self.realm}/authz/protection/permission",
            data=json.dumps(payload)
        )
        return raise_error_from_response(data, KeycloakPostError)

    def get_user_id(self, username) -> str:
        return self.keycloak_admin.get_user_id(username)

    def create_realm_role(self, role: str, skip_exists=True) -> str:
        payload = {
            "name": role,
            "clientRole": False
        }
        logger.info("Creating realm role: " + json.dumps(payload, indent=2))
        return self.keycloak_admin.create_realm_role(payload=payload, skip_exists=skip_exists)

    def assign_realm_roles_to_user(self, user_id: str, roles: list[str], skip_exists=True):
        if not isinstance(roles, list):
            roles = [roles]
        for r in roles:
            created_role = self.create_realm_role(r, skip_exists)
            logger.info("Created realm role: " + str(created_role))
        all_roles = self.keycloak_admin.get_realm_roles(brief_representation=False)
        realm_roles = list(filter(lambda role: role.get('name') in roles, all_roles))
        if not realm_roles:
            logger.warning("Warning: Realm roles " + str(roles) + " do no exist on realm " + self.realm)
            return
        realm_roles = [
            {
                "id": role.get('id'),
                "name": role.get('name'),
            } for role in realm_roles
        ]
        logger.info('Assigning roles to user ' + user_id + ':\n' + json.dumps(realm_roles, indent=2))
        return self.keycloak_admin.assign_realm_roles(user_id=user_id, roles=realm_roles)

    def create_client_role(self, client_id: str, role: str, skip_exists=True) -> str:
        payload = {
            "name": role,
            "clientRole": True
        }
        return self.keycloak_admin.create_client_role(client_role_id=client_id, payload=payload, skip_exists=skip_exists)

    def __get_service_account_user(self, client_id: str):
        data_raw = self.keycloak_admin.connection.raw_get(
            self.server_url + '/admin/realms/' + self.realm + '/clients/' + client_id + '/service-account-user')
        return raise_error_from_response(
            data_raw, KeycloakGetError
        )

    def get_policies(self,
                     resource: str = "",
                     name: str = "",
                     scope: str = "",
                     first: int = 0,
                     maximum: int = -1, ) -> list[str]:

        return self.keycloak_uma.policy_query(resource, name, scope, first, maximum)

    def get_client_authz_policies(self, client_id):
        _client_id = self.keycloak_admin.get_client_id(client_id)
        return self.keycloak_admin.get_client_authz_policies(_client_id)

    def update_policy(self, client_id, policy_id, payload):
        _client_id = self.keycloak_admin.get_client_id(client_id)
        params_path = {"realm-name": self.realm, "id": _client_id}
        policy_type = payload["type"]
        url = urls_patterns.URL_ADMIN_CLIENT_AUTHZ + "/policy/" + policy_type + "/" + policy_id
        data_raw = self.keycloak_admin.raw_put(url.format(**params_path), data=json.dumps(payload))
        return raise_error_from_response(
            data_raw, KeycloakPostError
        )

    def delete_policy(self, client_id, policy_id):
        _client_id = self.keycloak_admin.get_client_id(client_id)
        return self.keycloak_admin.delete_client_authz_policy(_client_id, policy_id)

    def get_client_authz_permissions(self, client_id):
        _client_id = self.keycloak_admin.get_client_id(client_id)
        return self.keycloak_admin.get_client_authz_permissions(_client_id)

    def get_client_management_permissions(self, client_id):
        _client_id = self.keycloak_admin.get_client_id(client_id)
        return self.keycloak_admin.get_client_management_permissions(_client_id)

    def get_client_resource_permissions(self, client_id):
        _client_id = self.keycloak_admin.get_client_id(client_id)
        params_path = {"realm-name": self.realm, "id": _client_id}
        url = urls_patterns.URL_ADMIN_CLIENT_AUTHZ + "/permission/resource"
        data_raw = self.keycloak_admin.raw_get(url.format(**params_path))
        return raise_error_from_response(
            data_raw, KeycloakGetError
        )

    # def get_client_authz_scope_permissions(self,client_id, scope_id):
    #    return self.keycloak_admin.get_client_authz_scope_permission(client_id, scope_id)

    # def create_client_authz_scope_based_permission(self, client_id, payload):
    #    return self.keycloak_admin.create_client_authz_scope_based_permission(client_id, payload)

    def create_client_authz_resource_based_permission(self, client_id, payload, skip_exists=False):
        _client_id = self.keycloak_admin.get_client_id(client_id)
        return self.keycloak_admin.create_client_authz_resource_based_permission(_client_id, payload, skip_exists=skip_exists)

    def update_client_management_permissions(self, client_id, payload):
        _client_id = self.keycloak_admin.get_client_id(client_id)
        return self.keycloak_admin.update_client_management_permissions(payload, _client_id)

    def update_client_authz_resource_permission(self, client_id, payload, permission_id):
        _client_id = self.keycloak_admin.get_client_id(client_id)
        params_path = {"realm-name": self.realm, "id": _client_id}
        url = urls_patterns.URL_ADMIN_CLIENT_AUTHZ + "/permission/resource/" + permission_id
        data_raw = self.keycloak_admin.raw_put(url.format(**params_path), data=json.dumps(payload))
        return raise_error_from_response(
            data_raw, KeycloakPutError
        )

    # def update_client_authz_scope_permission(self, client_id,  payload, scope_id):
    #    return self.keycloak_admin.update_client_authz_scope_permission(payload, client_id, scope_id)

    def get_client_scopes(self, client_id, name):
        _client_id = self.keycloak_admin.get_client_id(client_id)
        params_path = {"realm-name": self.realm, "id": _client_id}
        url = urls_patterns.URL_ADMIN_CLIENT_AUTHZ + "/scope/search?name=" + name
        data_raw = self.keycloak_admin.raw_get(url.format(**params_path))
        return raise_error_from_response(
            data_raw, KeycloakGetError
        )

    def create_client_scopes(self, client_id, payload, skip_exists=False):
        _client_id = self.keycloak_admin.get_client_id(client_id)
        params_path = {"realm-name": self.realm, "id": _client_id}
        url = urls_patterns.URL_ADMIN_CLIENT_AUTHZ + "/scope"
        data_raw = self.keycloak_admin.raw_post(url.format(**params_path), data=json.dumps(payload))
        return raise_error_from_response(
            data_raw, KeycloakPostError, skip_exists=skip_exists
        )

    def update_client_scopes(self, client_id, scope_id, payload):
        _client_id = self.keycloak_admin.get_client_id(client_id)
        params_path = {"realm-name": self.realm, "id": _client_id}
        url = urls_patterns.URL_ADMIN_CLIENT_AUTHZ + "/scope/" + scope_id
        data_raw = self.keycloak_admin.raw_put(url.format(**params_path), data=json.dumps(payload))
        return raise_error_from_response(
            data_raw, KeycloakPutError
        )

    def delete_client_scopes(self, client_id, scope_id):
        _client_id = self.keycloak_admin.get_client_id(client_id)
        params_path = {"realm-name": self.realm, "id": _client_id}
        url = urls_patterns.URL_ADMIN_CLIENT_AUTHZ + "/scope/" + scope_id
        data_raw = self.keycloak_admin.raw_delete(url.format(**params_path))
        return raise_error_from_response(
            data_raw
        )

    def delete_resource_permissions(self, client_id, permission_id):
        _client_id = self.keycloak_admin.get_client_id(client_id)
        params_path = {"realm-name": self.realm, "id": _client_id}
        url = urls_patterns.URL_ADMIN_CLIENT_AUTHZ + "/permission/resource/" + permission_id
        data_raw = self.keycloak_admin.raw_delete(url.format(**params_path))
        return raise_error_from_response(
            data_raw
        )

    def create_client(self, payload, skip_exists=True):
        return self.keycloak_admin.create_client(payload=payload, skip_exists=skip_exists)

    def generate_protection_pat(self, client_id, client_secret):
        """Generate a personal access token
        """
        payload = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        }
        connection = ConnectionManager(self.keycloak_uma.connection.base_url)
        connection.add_param_headers("Content-Type", "application/x-www-form-urlencoded")
        data_raw = connection.raw_post(self.keycloak_uma.uma_well_known["token_endpoint"], data=payload)
        return raise_error_from_response(data_raw, KeycloakPostError)


    def create_permission_ticket(self, resources: [str]):
        payload = [
            {"resource_id": resource} for resource in resources
        ]
        params_path = {"realm-name": self.realm}
        url = "/realms/{realm-name}/authz/protection/permission"
        data_raw = self.keycloak_admin.raw_post(url.format(**params_path), data=json.dumps(payload))
        return raise_error_from_response(
            data_raw, KeycloakPostError
        )

    def get_rpt(self, client_id, client_secret, token, ticket):
        payload = {
            "claim_token_format": "http://openid.net/specs/openid-connect-core-1_0.html#IDToken",
            "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
            "claim_token": token,
            "ticket": ticket,
            "client_id": client_id,
            "client_secret": client_secret
        }
        params_path = {
            "realm-name": self.realm
        }
        connection = ConnectionManager(self.keycloak_uma.connection.base_url)
        connection.add_param_headers("Content-Type", "application/x-www-form-urlencoded")
        data = connection.raw_post(urls_patterns.URL_TOKEN.format(**params_path), data=payload)
        return raise_error_from_response(data, KeycloakPostError)