#!/bin/bash

json_array() {
  echo -n '['
  while [ $# -gt 0 ]; do
    x=${1//\\/\\\\}
    echo -n "\"${x//\"/\\\"}\""
    [ $# -gt 1 ] && echo -n ', '
    shift
  done
  echo ']'
}

read -rp "Client Id: " client_id
read -rp "Client Name: " client_name
read -rp "Client Description: " client_description
read -rp "Add resource? [y/N] " add_resource
resources=()
while [ "$add_resource" == y ]; do
  read -rp "Resource name: " resource_name
  read -rp "Resource URIs: " resource_uris
  read -rp "Resource scopes (optional): " resource_scopes
  if [ -z "${resource_scopes}" ]; then
    resource_scopes="access"
  fi
  read -rp "Users: " users
  read -rp "Roles: " roles
  echo "test"
  IFS=',' read -ra resource_uris_array <<<"$resource_uris"
  IFS=',' read -ra resource_scopes_array <<<"$resource_scopes"
  IFS=',' read -ra users_array <<<"$users"
  IFS=',' read -ra roles_array <<<"$roles"
  if ((${#users_array[@]} == 0 && ${#roles_array[@]} == 0)); then
    echo "Resource permission requires at least one user or role... skipping"
  else
    resource="{
            \"resource\": {
              \"name\": \"${resource_name}\",
              \"uris\": $(json_array "${resource_uris_array[@]}"),
              \"resource_scopes\": $(json_array "${resource_scopes_array[@]}")
            },
            \"permissions\": {
              \"user\": $(json_array "${users_array[@]}"),
              \"role\": $(json_array "${roles_array[@]}")
            }
          }"
        resources+=("$resource")
  fi
  read -rp "Add resource? [y/N] " add_resource
done
payload=""
if ((${#resources[@]} == 0)); then
  payload="{
        \"clientId\": \"${client_id}\",
        \"name\": \"${client_name}\",
        \"description\": \"${client_description}\"
      }"
else
  payload="{
    \"clientId\": \"${client_id}\",
    \"name\": \"${client_name}\",
    \"description\": \"${client_description}\",
    \"resources\": [${resources[*]}]
  }"
fi
echo $payload