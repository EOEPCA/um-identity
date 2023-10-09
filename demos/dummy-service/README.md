# peptest

Simulates the use of nginx `auth_request` to defer the authorization decision for each request to the PEP. The flows are as follows...

![Nginx auth_request](uml/export/Nginx%20auth_request.png "Nginx auth_request")

The scenario is simulated through the following endpoints that are instantiated through docker-compose, see [docker-compose.yml](docker-compose.yml)...

* **nginx**<br>
  Nginx instance configured through this [nginx.conf](nginx/nginx.conf), exposed to the host on port 80
* **pep**<br>
  Instance of test program `peptest` in mode `'-auth'`, which provides the `auth_request` endpoint and mocks the PEP logic.<br>
  **_To aid testing, the PEP uses the integer value of the Bearer token to determine the result of the authorization decision, i.e. the http status code to be returned._**
* **ades**<br>
  Instance of test program `peptest` in mode `'-resource'`, which provides the Resource Server endpoint and mocks the ADES

## nginx.conf

The nginx instance uses the configuration file [nginx/nginx.conf](nginx/nginx.conf), which can be summarised as follows...

* **location /ades**<br>
  Proxies to the 'ades' service.<br>
  Specifies `auth_request` directive using the `/authcheck` internal endpoint.
* **location /authcheck**<br>
  Specifies the handling of the `auth_request` directive to be deferred to the 'pep' endpoint.

## Running the services

Requires docker-compose. The services are started by running...
```console
$ ./run.sh
```

The `peptest` image is built, services are up'd, and `docker logs` runs to see the `stdout` of the services.

## Testing the endpoints

The file [requests/requests.http](requests/requests.http) provides sample requests for the various cases - which can be executed, for example, with the vscode REST Client extension - [humao.rest-client](https://marketplace.visualstudio.com/items?itemName=humao.rest-client).

Alternatively, the directory [requests/](requests/) contains shell scripts to execute equivalent `curl` commands.

## Stopping the services

The scenario is stopped by running...
```console
$ ./stop.sh
```
