#!/bin/bash

usage="$(basename "$0") [-h] [--clientid id] [--clientname name] [--resourcename name] [--resourceuris u1,u2] [--scopes s] [--users u1,u2] [--roles r1,r2] -- add a client with protected resources

where:
    -h                  show help message
    --default-resource  add default resource - /* authenticated
    --clientid          client id
    --clientname        client name
    --resourcename      resource name
    --resourceuris      resource uris - separated by comma (,)
    --scopes            resource scopes - separated by comma (,)
    --users             user names with access to the resource - separated by comma (,)
    --roles             role names with access to the resource - separated by comma (,)
"

client_id=""
client_name=""
resource_name=""
resource_uris=()
resource_scopes=()
users=()
roles=()

resources=()

while test $# -gt 0; do
           case "$1" in
                --clientid)
                    shift
                    if [ ! -z "${client_id}" ]; then
                      add_resource()
                    fi
                    client_id=$1
                    shift
                    ;;
                --clientname)
                    shift
                    if [ ! -z "${client_name}" ]; then
                      add_resource()
                    fi
                    client_name=$1
                    shift
                    ;;
                --resourcename)
                    shift
                    resource_name=$1
                    shift
                    ;;
                --default-resource)
                    shift
                    resource_uris=("/*")
                    resource_scopes=()
                    users=()
                    roles=()
                    add_resource()
                    shift
                    ;;
                --resourceuris)
                    shift
                    resource_uris=$1
                    shift
                    ;;
                --scopes)
                    shift
                    resource_scopes=$1
                    shift
                    ;;
                --users)
                    shift
                    users=$1
                    shift
                    ;;
                --roles)
                    shift
                    roles=$1
                    shift
                    ;;
                -h)
                    echo "$usage"
                    return 1;
                    ;;
                *)
                   echo "$usage"
                   return 1;
                   ;;
          esac
done


if (( ${#resources[@]} == 0 )); then
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
fi


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

add_resource() {
  IFS=',' read -ra resource_uris_array <<<"$resource_uris"
  IFS=',' read -ra resource_scopes_array <<<"$resource_scopes"
  IFS=',' read -ra users_array <<<"$users"
  IFS=',' read -ra roles_array <<<"$roles"
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
  client_id=""
  client_name=""
  resource_name=""
  resource_uris=()
  resource_scopes=()
  users=()
  roles=()
}

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