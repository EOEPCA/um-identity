#!/bin/bash
i=0
resource_names_list=()
resource_uris_list=()
resource_scopes_list=()
users_list=()
roles_list=()

while test $# -gt 0; do
           case "$1" in
                -clientid)
                    shift
                    client_id=$1
                    shift
                    ;;
                -clientname)
                    shift
                    client_name=$1
                    shift
                    ;;
                -resourcename) 
                    shift
                    resource_names_list[$i]=$1
                    i=$(($i+1))
                    shift
                    ;;
                -resourceuris) 
                    shift
                    resource_uris_list[$i]=$1
                    shift
                    ;;
                -scopes) 
                    shift
                    resource_scopes_list[$i]=$1
                    shift
                    ;;
                -users) 
                    shift
                    users_list[$i]=$1
                    shift
                    ;;
                -roles) 
                    shift
                    roles_list[$i]=$1
                    shift
                    ;;
                *)
                   echo "$1 is not a recognized flag!"
                   return 1;
                   ;;
          esac
done  

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

echo ${resource_names_list[@]}
echo ${resource_uris_list[@]}
echo ${users_list[@]}
echo ${roles_list[@]}


resources=()
for ind in "${!resource_names_list[@]}"; do

  resource_name=${resource_names_list[ind]}
  resource_uris=${resource_uris_list[ind]}
  resource_scopes=${resource_scopes_list[ind]}
  users=${users_list[ind]}
  roles=${roles_list[ind]}

  if [ -z "${resource_scopes}" ]; then
    resource_scopes="access"
  fi
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