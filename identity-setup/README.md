# Identity setup

Script to set up the Identity.

- Registers default realms
- Registers default users
- Registers needed clients
- Registers default resources

### Build and Execute

```shell
docker build -f identity-setup/Dockerfile . -t identity-setup
docker run --rm -d --name identity-setup identity-setup
```
