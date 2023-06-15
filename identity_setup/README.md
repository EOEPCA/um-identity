# Keycloak setup

Python script to setup the Identity.

- Registers default users
- Registers needed clients
- Registers default resources

### Build and Execute

```shell
docker build -f identity_setup/Dockerfile . -t identity-setup
docker run --rm -d --name identity-setup identity-setup
```
