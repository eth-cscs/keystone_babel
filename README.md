## A proxy for OpenStack Keystone that hides exotic identity providers

This application is a Keystone proxy that masks a 2-step authentication
 process (SAML in this case, but OIDC is similar) behind a regular 
 username/password authentication

The reason for doing this is the fact that, even though federated
 authentication is supported in v3, and integrated in the python client,
 still many clients are unable to support it. Some examples are rclone 
 and Cyberduck.

By deploying this "companion" service, you can use the standard keystone
 regularly and point to this service only whenever you have a client that
 does not implement the two steps.

There may be some limitations to this approach: e.g. you can only use it 
 with one single federated IdP, unless you implement a way to distinguish 
 between them by looking at the request (which is possible)

You can use this application in two ways:
1. In your own machine, as a client, without intervention from the SP
2. Near your Keystone server, as a service provider, to help clients

### Usage example

1. Edit `keystone_babel.py` to match your setup.
2. Start the proxy server via `./keystone_babel.py`
3. Configure your OpenStack client to use the proxy as auth-url:
```
export OS_AUTH_URL="http://127.0.0.1:5000/v3"
export OS_USERNAME="<your_username>"
export OS_PASSWORD="<your_password>"
export OS_PROJECT_ID="<your_project_id>"
```

Instead of `OS_PROJECT_ID` you can also use:
```
export OS_PROJECT_NAME="<your_project_name>"
export OS_PROJECT_DOMAIN_NAME="<your_project_domain>"
```
