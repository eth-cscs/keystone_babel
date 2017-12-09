#!/usr/bin/env python
# -*- coding: utf-8 -*-


# This application is a Keystone proxy that masks a 2-step authentication
#  process (SAML in this case, but OIDC is similar) behind a regular 
#  username/password authentication
# The reason for doing this is the fact that, even though federated
#  authentication is supported in v3, and integrated in the python client,
#  still many clients are unable to support it.
# By deploying this "companion" service, you can use the standard keystone
#  regularly and point to this service only whenever you have a client that
#  does not implement the two steps.
# There may be some limitations to this approach: e.g. you can only use it 
#  with one single federated IdP, unless you implement a way to distinguish 
#  between them by looking at the request (which is possible)

# Changelog
# v0.2 - 2017-12-09 - Pablo Fernandez (CSCS/ETHZ)
#  - Proxy all requests to the original keystone
#  - Implemented V2 for Cyberduck support
#  - Operates only when the authentication comes with password (and proxy otherwise)
#  - SSL support
#
# v0.1 - 2017-11-24 - Ole Schütt (MARVEL/EMPA)
#  - First functional version
#  - Takes the user password, performs the SAML exchange and gets the final token
#  - Works with rclone

# Libs
import flask
import requests
from flask import request
from keystoneauth1.extras._saml2 import V3Saml2Password
from keystoneauth1.identity.v3 import Token
from keystoneauth1 import session
try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse


app = flask.Flask(__name__)

# Params
REAL_KEYSTONE = 'pollux.cscs.ch:13000'
OS_IDENTITY_PROVIDER = 'cscskc'
OS_IDENTITY_PROVIDER_URL = 'https://kc.cscs.ch/auth/realms/cscs/protocol/saml/'
OS_PROTOCOL = 'mapped'
OS_INTERFACE = 'public'
enable_ssl = True
DEFAULT_DOMAIN = 'cscs' # for keystoneV2 only


#===============================================================================
# Helper function to re-do the request we've received to the real Keystone 
def proxy():
    # replace url with that of the real keystone
    spliturl=list(urlparse.urlsplit(request.url))
    spliturl[0] = 'https'  # the real keystone is most likely behind SSL
    spliturl[1] = REAL_KEYSTONE
    url = urlparse.urlunsplit(spliturl)
    #print "PROXY"

    # do the request
    resp = requests.request(
        method=request.method,
        url=url,
        headers={key: value for (key, value) in request.headers if key != 'Host'},
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False)

    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers = [(name, value) for (name, value) in resp.raw.headers.items()
               if name.lower() not in excluded_headers]

    return flask.Response(resp.content, resp.status_code, headers)


#===============================================================================
# This is the default landing place. We basically:
#  1. Check if the request is a password request
#  2. If it is, we get an unscoped token with SAML
#  3. With the scoped token, we re-do the intial request replacing the password
#      auth
#  4. Return the output to the user
@app.route('/v3/auth/tokens', methods=['POST'])
def v3tokens():
    # parse request
    body = flask.request.get_json()
    headers = flask.request.headers
    #print "IN v3tokens", body

    # Bypass requests without a password inside (e.g. for unscoped-to-scoped auth)
    if 'password' not in body['auth']['identity']:
        return proxy()

    # Get the input from the body
    user = body['auth']['identity']['password']['user']
    username = user['name']
    password = user['password']

    # get unscoped token via SAML
    auth = V3Saml2Password(auth_url='https://'+REAL_KEYSTONE+'/v3',
                           identity_provider=OS_IDENTITY_PROVIDER,
                           protocol=OS_PROTOCOL,
                           identity_provider_url=OS_IDENTITY_PROVIDER_URL,
                           username=username,
                           password=password)
    #print auth.get_auth_state()
    sess = session.Session(auth=auth)
    token = sess.get_token(auth)
    #print auth.get_headers(sess)
    #token = sess.get_auth_headers()['X-Auth-Token']
    #print token

    # patch original body (and keep the rest of the request)
    del(body['auth']['identity'])
    body['auth']['identity'] = {"methods": ["token"],
                                "token": {"id": token}}

    # get scoped token (or unscoped, depending on the original request)
    r = requests.post('https://'+REAL_KEYSTONE+'/v3/auth/tokens', json=body, headers=headers)

    # forward response
    return flask.Response(r.text, headers=dict(r.headers), status=r.status_code)


#===============================================================================
# This is to support Cyberduck, which uses by default the deprecated V2
# It follows a similar process, but with just one request. Because of this, 
#  we need to detect if the request is scoped or not and act accordingly
@app.route('/v2.0/tokens', methods=['POST'])
def v2tokens():
    # parse request
    body = flask.request.get_json()
    headers = flask.request.headers

    # Bypass requests without a password inside (e.g. for unscoped-to-scoped auth)
    if 'passwordCredentials' not in body['auth']:
        return proxy()

    # Get the input from the body
    username = body['auth']['passwordCredentials']['username']
    password = body['auth']['passwordCredentials']['password']

    # Check if the request is for a scoped token:
    tenantId = None
    tenantName = None
    isScoped = False
    if 'tenantId' in body['auth']: 
        tenantId = body['auth']['tenantId']
        tenantDomain = None
        isScoped = True
    if 'tenantName' in body['auth']: 
        tenantName = body['auth']['tenantName']
        tenantDomain = DEFAULT_DOMAIN
        isScoped = True

    # get unscoped token via SAML
    auth = V3Saml2Password(auth_url='https://'+REAL_KEYSTONE+'/v3',
                           identity_provider=OS_IDENTITY_PROVIDER,
                           protocol=OS_PROTOCOL,
                           identity_provider_url=OS_IDENTITY_PROVIDER_URL,
                           # The next 3 are for scoped tokens 
                           project_id=tenantId,
                           project_name=tenantName,
                           project_domain_name=tenantDomain,
                           username=username,
                           password=password)
    sess = session.Session(auth=auth)
    token = sess.get_token()
    if isScoped: 
        # From now on, we just need to work with the Project ID, not the name
        tenantID=sess.get_project_id()

    # create new body to get the catalog without the password
    newbody = {'auth' : {'token': {'id': token} } }
    if isScoped:
        # Otherwise we get an empty service catalog and nothing works
        newbody['auth']['tenantId'] = tenantID

    # resubmit request
    r = requests.post('https://'+REAL_KEYSTONE+'/v2.0/tokens', json=newbody, headers=headers)

    # forward response
    return flask.Response(r.text, headers=dict(r.headers), status=r.status_code)

#===============================================================================
# We seem to need to put ourselves in the response in this case, let's hope it's 
#  the only place
@app.route('/v3')
def v3():
    #print "IN v3"
    resp = proxy()
    # Replace remote keystone host with ourselves
    content = resp.get_data(as_text=True).replace(REAL_KEYSTONE, request.host)
    resp.set_data(content)
    return resp

# Do we need to implement / forward entire keystone API? Let's hope this is enough:
# https://developer.openstack.org/api-ref/identity/v3/
#===============================================================================
@app.route('/<path:url>')
def other(url):
    #print "IN other"
    return proxy()

# TODO: do we need to patch the whole service catalog? Let's hope not!

#===============================================================================
# MAIN
if __name__ == "__main__":
    if enable_ssl:
        #app.run(host='0.0.0.0', port=13000, ssl_context=('yourserver.crt', 'yourserver.key'), debug=True)
        app.run(host='0.0.0.0', port=13000, ssl_context='adhoc', debug=True)
    else:
        app.run(host='0.0.0.0', port=13000, debug=True)
#EOF
