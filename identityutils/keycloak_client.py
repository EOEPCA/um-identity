import json
import logging
import os
from keycloak import KeycloakOpenID, KeycloakOpenIDConnection, KeycloakAdmin, KeycloakUMA, ConnectionManager, \
    urls_patterns
from keycloak.exceptions import raise_error_from_response, KeycloakGetError, KeycloakPostError, KeycloakPutError
from .logger import Logger

Logger.get_instance().load_configuration(os.path.join(os.path.dirname(__file__), "../logging.yml"))
logger = logging.getLogger("IDENTITY_UTILS")

class KeycloakClient:

    def __init__(self, server_url, realm, resource_server_endpoint, username, password):
        if 'https' not in server_url and '/auth' not in server_url:
            server_url = server_url
        self.server_url = server_url
        self.realm = realm
        self.resource_server_endpoint = resource_server_endpoint
        openid_connection = KeycloakOpenIDConnection(
            server_url=self.server_url,
            username=username,
            password=password,
            verify=self.server_url.startswith('https'),
            timeout=10)
        self.keycloak_admin = KeycloakAdmin(connection=openid_connection)
        self.admin_client = None
        self.resources_client = None
        self.oauth2_proxy_client = None
        self.keycloak_uma = None
        self.keycloak_uma_openid = None
        self.set_realm(realm)
        # we have one admin client to do admin REST API calls
        admin_client_id = self.keycloak_admin.get_client_id('admin-cli')
        self.admin_client = self.keycloak_admin.get_client(admin_client_id)
        openid_connection = KeycloakOpenIDConnection(
            server_url=self.server_url,
            user_realm_name="master",
            realm_name=self.realm,
            username=self.keycloak_admin.username,
            password=self.keycloak_admin.password,
            client_id=self.admin_client.get('clientId'),
            verify=self.server_url.startswith('https'),
            timeout=10)
        self.keycloak_admin = KeycloakAdmin(connection=openid_connection)
        self.__register_resources_client('resources-management')

    def set_realm(self, realm):
        if realm != 'master':
            self.keycloak_admin.create_realm(payload={"realm": self.realm, "enabled": True}, skip_exists=True)
        self.keycloak_admin.realm_name = self.realm

    def import_realm(self, realm: dict) -> dict:
        return self.keycloak_admin.import_realm(realm)

    def register_resources(self, resources):
        if not isinstance(resources, list):
            resources = [resources]
        for resource in resources:
            self.register_resource(resource)

    def register_resource(self, resource, client_id):
        print("here=====>>>>>>>>")
        print("here=====>>>>>>>>",client_id)
        _client_id = self.keycloak_admin.get_client_id(client_id)
        print("here=====>>>>>>>>",_client_id)
        client_id = self.resources_client.get("id")
        print("here=====>>>>>>>>",client_id)
        response = self.keycloak_admin.create_client_authz_resource(client_id=client_id, payload=resource,
                                                                    skip_exists=True)
        logger.info('Created resource:\n' + json.dumps(resource, indent=2))
        logger.info('Response: ' + str(response))
        return response


    def update_resource(self, resource_id, resource, client_id):
        _client_id = self.keycloak_admin.get_client_id(client_id)
        if "_id" not in resource:
            resource["_id"] = resource_id
        elif resource["_id"] != resource_id:
            raise KeycloakGetError(
                error_message="Resource ids on path and body don't matc", response_code=400, response_body=bytearray()
            )
        params_path = {"realm-name": self.realm, "id": client_id}
        url = urls_patterns.URL_ADMIN_CLIENT_AUTHZ + "/resource/" + resource_id
        data_raw = self.keycloak_admin.connection.raw_put(url.format(**params_path), data=json.dumps(resource))
        return raise_error_from_response(data_raw, KeycloakPutError, expected_codes=[204])

    def delete_resource(self, resource_id, client_id):
        _client_id = self.keycloak_admin.get_client_id(client_id)
        params_path = {"realm-name": self.realm, "id": client_id}
        url = urls_patterns.URL_ADMIN_CLIENT_AUTHZ + "/resource/" + resource_id
        data_raw = self.keycloak_admin.connection.raw_delete(url.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakPutError)

    def delete_policies(self, policies, client_id):
        if not isinstance(policies, list):
            policies = [policies]
            logger.info("Deleting policies: " + str(policies))
        _client_id = self.keycloak_admin.get_client_id(client_id)
        delete_policies = list(filter(lambda p: p.get('name') in policies, self.keycloak_admin.get_client_authz_policies(client_id)))
        logger.info("Policies to delete: " + str(delete_policies))
        if not delete_policies:
            logger.info("Policies not found: " + str(policies))
            return
        for d in delete_policies:
            self.keycloak_admin.delete_client_authz_policy(client_id=client_id, policy_id=d.get('id'))

    def __register_policy(self, policy, register_f, client_id):
        _client_id = self.keycloak_admin.get_client_id(client_id)
        logger.info("Creating policy:\n" + json.dumps(policy, indent=2))
        response = register_f(client_id=client_id, payload=policy, skip_exists = True)
        logger.info("Response: " + str(response))
        return response

    def __register_policy_send_post(self, policy_type, client_id, payload, skip_exists):
        params_path = {"realm-name": self.realm, "id": client_id}
        url = urls_patterns.URL_ADMIN_CLIENT_AUTHZ + "/policy/" + policy_type + "?max=-1"
        data_raw = self.keycloak_admin.connection.raw_post(url.format(**params_path), data=json.dumps(payload))
        return raise_error_from_response(
            data_raw, KeycloakPostError, expected_codes=[201], skip_exists=skip_exists
        )

    def register_aggregated_policy(self, policy):
        # strategy: UNANIMOUS | AFFIRMATIVE | CONSENSUS
        if not isinstance(policy, list):
            policy = [policy]
        return self.__register_policy(policy, lambda client_id, payload, skip_exists: self.__register_policy_send_post("aggregate", client_id, payload, skip_exists))

    def register_client_policy(self, policy, client_id):
        policy_type = "client"
        _client_id = self.keycloak_admin.get_client_id(client_id)
        policy["clients"] = [client_id]
        params_path = {"realm-name": self.realm, "id": client_id}
        url = urls_patterns.URL_ADMIN_CLIENT_AUTHZ + "/policy/" + policy_type + "?max=-1"
        data_raw = self.keycloak_admin.raw_post(url.format(**params_path), data=json.dumps(policy))
        return raise_error_from_response(
            data_raw, KeycloakPostError, expected_codes=[201, 409], skip_exists=True
        )

    def register_client_scope_policy(self, policy, client_id):
        policy_type = "client-scope"
        _client_id = self.keycloak_admin.get_client_id(client_id)
        policy["owner"] = client_id
        params_path = {"realm-name": self.realm, "id": client_id}
        url = urls_patterns.URL_ADMIN_CLIENT_AUTHZ + "/policy/" + policy_type + "?max=-1"
        data_raw = self.keycloak_admin.raw_post(url.format(**params_path), data=json.dumps(policy))
        return raise_error_from_response(
            data_raw, KeycloakPostError, expected_codes=[201, 409], skip_exists=True
        )

    def register_group_policy(self, policy):
        # groups: [{"id": str, "path": str}]
        return self.__register_policy(policy, lambda client_id, payload, skip_exists: self.__register_policy_send_post("group", client_id, payload, skip_exists))

    def register_regex_policy(self, policy):   
        return self.__register_policy(policy, lambda client_id, payload, skip_exists: self.__register_policy_send_post("regex", client_id, payload, skip_exists))

    def register_role_policy(self, policy):
        if not isinstance(roles, list):
            roles = [roles]
        
        return self.__register_policy(policy, self.keycloak_admin.create_client_authz_role_based_policy)

    def register_time_policy(self, name, time):
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
        policy = {
            "type": "time",
            "logic": "POSITIVE",
            "decisionStrategy": "UNANIMOUS",
            "name": name,
            "description": ""
        }
        policy.update(time)
        return self.__register_policy(policy, lambda client_id, payload, skip_exists: self.__register_policy_send_post("time", client_id, payload, skip_exists))

    def register_user_policy(self, name, users):
        if not isinstance(users, list):
            users = [users]
        policy = {
            "type": "user",
            "logic": "POSITIVE",
            "decisionStrategy": "UNANIMOUS",
            "name": name,
            "users": users,
            "description": ""
        }
        return self.__register_policy(policy, lambda client_id, payload, skip_exists: self.__register_policy_send_post("user", client_id, payload, skip_exists))

    def assign_resources_permissions(self, permissions, client_id):
        if not isinstance(permissions, list):
            permissions = [permissions]
        _client_id = self.keycloak_admin.get_client_id(client_id)
        for permission in permissions:
            response = self.keycloak_admin.create_client_authz_resource_based_permission(client_id=client_id,
                                                                                         payload=permission,
                                                                                         skip_exists=True)
            logger.info("Creating resource permission: " + json.dumps(permission, indent=2))
            logger.info("Response: " + str(response))

    def create_user(self, username, password, realm_roles=None) -> str:
        if realm_roles is None:
            realm_roles = []
        if not isinstance(realm_roles, list):
            realm_roles = [realm_roles]
        payload = {
            "username": username,
            "enabled": True
        }
        logger.info('Registering user: ' + json.dumps(payload, indent=2))
        user_id = self.keycloak_admin.create_user(payload, exist_ok=True)
        logger.info('Created user: ' + str(user_id))
        logger.info("Changing password for user: " + str(user_id))
        self.keycloak_admin.set_user_password(user_id, password, temporary=False)
        if realm_roles:
            self.assign_realm_roles_to_user(user_id, realm_roles)
        return user_id

    def get_user_token(self, username, password, openid):
        """Gets a user token using username/password authentication.
        """
        return openid.token(username, password, scope="openid profile")

    def generate_protection_pat(self):
        """Generate a personal access token
        """
        payload = {
            "grant_type": "client_credentials",
            "client_id": self.resources_client.get('clientId'),
            "client_secret": self.resources_client.get('secret'),
        }
        connection = ConnectionManager(self.keycloak_uma.connection.base_url)
        connection.add_param_headers("Content-Type", "application/x-www-form-urlencoded")
        data_raw = connection.raw_post(self.keycloak_uma.uma_well_known["token_endpoint"], data=payload)
        return raise_error_from_response(data_raw, KeycloakPostError)

    def get_resources(self,
                      name: str = "",
                      exact_name: bool = False,
                      uri: str = "",
                      owner: str = "",
                      resource_type: str = "",
                      scope: str = "",
                      first: int = 0,
                      maximum: int = -1) -> list[str]:
        if not name and not uri and not owner and not resource_type and not scope and first == 0 and maximum == -1:
            return list(self.keycloak_uma.resource_set_list())

        return self.__query_resources(name=name, exact_name=exact_name, uri=uri, owner=owner,
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

    def get_rpt(self, access_token, ticket, limits):
        payload = {
            "claim_token_format": "urn:ietf:params:oauth:token-type:jwt",
            "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
            "claim_token": access_token,
            "ticket": ticket,
            "client_id": self.resources_client.get('clientId'),
            "client_secret": self.resources_client.get('secret'),
            "response_permissions_limit": limits
        }
        params_path = {
            "realm-name": self.realm
        }
        connection = ConnectionManager(self.keycloak_uma.connection.base_url)
        connection.add_param_headers("Content-Type", "application/x-www-form-urlencoded")
        data = connection.raw_post(urls_patterns.URL_TOKEN.format(**params_path), data=payload)
        return raise_error_from_response(data, KeycloakPostError)

    def get_user_id(self, username) -> str:
        return self.keycloak_admin.get_user_id(username)

    def create_realm_role(self, role: str) -> str:
        payload = {
            "name": role,
            "clientRole": False
        }
        logger.info("Creating realm role: " + json.dumps(payload, indent=2))
        return self.keycloak_admin.create_realm_role(payload=payload, skip_exists=True)

    def assign_realm_roles_to_user(self, user_id: str, roles: list[str]):
        if not isinstance(roles, list):
            roles = [roles]
        for r in roles:
            created_role = self.create_realm_role(r)
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
        self.keycloak_admin.assign_realm_roles(user_id=user_id, roles=realm_roles)

    def create_client_role(self, client_id: str, role: str) -> str:
        payload = {
            "name": role,
            "clientRole": True
        }
        return self.keycloak_admin.create_client_role(client_role_id=client_id, payload=payload, skip_exists=True)

    def register_client(self, options: dict):
        client_id = self.keycloak_admin.create_client(payload=options, skip_exists=True)
        client = self.keycloak_admin.get_client(client_id)
        logger.info('Created client:\n' + json.dumps(client, indent=2))
        if options.get('serviceAccountsEnabled'):
            user = self.__get_service_account_user(client['id'])
            user_id = user.get('id')
            logger.info('Created service account user:\n' + json.dumps(user, indent=2))
        return client

    def __register_resources_client(self, client_id: str):
        options = {
            'clientId': client_id,
            'secret': 'secret',  # TODO changeme
            'serviceAccountsEnabled': True,
            'directAccessGrantsEnabled': True,
            'authorizationServicesEnabled': True,
            'authorizationSettings': {
                'allowRemoteResourceManagement': False, # True
                'policyEnforcementMode': 'ENFORCING'
            },
            "bearerOnly": False,
            'adminUrl': self.resource_server_endpoint,
            'baseUrl': self.resource_server_endpoint,
            'redirectUris': [
                #self.resource_server_endpoint + '/*'
                '*'
            ]
        }
        self.resources_client = self.register_client(options=options)
        self.keycloak_uma = KeycloakUMA(connection=KeycloakOpenIDConnection(
            server_url=self.server_url,
            realm_name=self.realm,
            client_id=self.resources_client.get('clientId'),
            client_secret_key=self.resources_client.get('secret'),
            verify=self.server_url.startswith('https')
        ))
        self.keycloak_uma_openid = KeycloakOpenID(server_url=self.server_url,
                                                  realm_name=self.realm,
                                                  client_id=self.resources_client.get('clientId'),
                                                  client_secret_key=self.resources_client.get('secret'))
        return self.resources_client

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
                    maximum: int = -1,) -> list[str]:

        return self.keycloak_uma.policy_query(resource, name, scope, first, maximum)
    
    def get_client_authz_policies(self, client_id):
        _client_id = self.keycloak_admin.get_client_id(client_id)
        return self.keycloak_admin.get_client_authz_policies(client_id)
    
    def update_policy(self, policy_id, payload, client_id):
        _client_id = self.keycloak_admin.get_client_id(client_id)
        params_path = {"realm-name": self.realm, "id": client_id}
        policy_type = payload["type"]
        url = urls_patterns.URL_ADMIN_CLIENT_AUTHZ + "/policy/" + policy_type +"/"+policy_id
        data_raw = self.keycloak_admin.raw_put(url.format(**params_path), data=json.dumps(payload))
        return raise_error_from_response(
            data_raw, KeycloakPostError
        )
    
    def delete_policy(self, policy_id, client_id):
        _client_id = self.keycloak_admin.get_client_id(client_id)
        return self.keycloak_admin.delete_client_authz_policy(client_id, policy_id)
    
    def get_client_authz_permissions(self, client_id):
        return self.keycloak_admin.get_client_authz_permissions(client_id)

    def get_client_management_permissions(self, client_id):
        return self.keycloak_admin.get_client_management_permissions(client_id)
    
    def get_client_resource_permissions(self, client_id):
        params_path = {"realm-name": self.realm, "id": client_id}
        url = urls_patterns.URL_ADMIN_CLIENT_AUTHZ + "/permission/resource"
        data_raw = self.keycloak_admin.raw_get(url.format(**params_path))
        return raise_error_from_response(
            data_raw, KeycloakGetError
        )
    
    #def get_client_authz_scope_permissions(self,client_id, scope_id):
    #    return self.keycloak_admin.get_client_authz_scope_permission(client_id, scope_id)
    
    #def create_client_authz_scope_based_permission(self, client_id, payload):
    #    return self.keycloak_admin.create_client_authz_scope_based_permission(client_id, payload, skip_exists=True)
    
    def create_client_authz_resource_based_permission(self, client_id, payload):
        return self.keycloak_admin.create_client_authz_resource_based_permission(client_id, payload, skip_exists=True)

    def update_client_management_permissions(self, client_id, payload):
        return self.keycloak_admin.update_client_management_permissions(payload, client_id)
    
    def update_client_authz_resource_permission(self, client_id, payload, permission_id):
        params_path = {"realm-name": self.realm, "id": client_id}
        url = urls_patterns.URL_ADMIN_CLIENT_AUTHZ + "/permission/resource/" + permission_id
        data_raw = self.keycloak_admin.raw_put(url.format(**params_path), data = json.dumps(payload))
        return raise_error_from_response(
            data_raw, KeycloakPutError
        )
    
    #def update_client_authz_scope_permission(self, client_id,  payload, scope_id):
    #    return self.keycloak_admin.update_client_authz_scope_permission(payload, client_id, scope_id)
    
    def get_client_scopes(self, client_id, name):
        params_path = {"realm-name": self.realm, "id": client_id}
        url = urls_patterns.URL_ADMIN_CLIENT_AUTHZ + "/scope/search?name=" + name
        data_raw = self.keycloak_admin.raw_get(url.format(**params_path))
        return raise_error_from_response(
            data_raw, KeycloakGetError
        )
    
    def create_client_scopes(self, client_id, payload):
        params_path = {"realm-name": self.realm, "id": client_id}
        url = urls_patterns.URL_ADMIN_CLIENT_AUTHZ + "/scope"
        data_raw = self.keycloak_admin.raw_post(url.format(**params_path), data = json.dumps(payload))
        return raise_error_from_response(
            data_raw, KeycloakPostError
        )
    
    def update_client_scopes(self, client_id, scope_id, payload):
        params_path = {"realm-name": self.realm, "id": client_id}
        url = urls_patterns.URL_ADMIN_CLIENT_AUTHZ + "/scope/" + scope_id
        data_raw = self.keycloak_admin.raw_put(url.format(**params_path), data = json.dumps(payload))
        return raise_error_from_response(
            data_raw, KeycloakPutError
        )
    
    def delete_client_scopes(self, client_id, scope_id):
        params_path = {"realm-name": self.realm, "id": client_id}
        url = urls_patterns.URL_ADMIN_CLIENT_AUTHZ + "/scope/" + scope_id
        data_raw = self.keycloak_admin.raw_delete(url.format(**params_path))
        return raise_error_from_response(
            data_raw
        )
    
    

    