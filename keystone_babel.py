#!/usr/bin/env python
# -*- coding: utf-8 -*-


import flask
import requests

from flask import request

from keystoneauth1.extras._saml2 import V3Saml2Password
from keystoneauth1.identity.v3 import Token
from keystoneauth1 import session
from urlparse import urlsplit, urlunsplit

app = flask.Flask(__name__)

REAL_KEYSTONE = 'pollux-tds.cscs.ch:13000'
OS_IDENTITY_PROVIDER = 'cscskc'
OS_IDENTITY_PROVIDER_URL = 'https://kc-tds.cscs.ch/auth/realms/cscs/protocol/saml/'
OS_PROTOCOL = 'mapped'
OS_INTERFACE = 'public'
enable_ssl = True
DEFAULT_DOMAIN = 'cscs' # for keystoneV2 only

# TODO make this work for users getting the scoped token directly with a password
#  For this most of the V2 work can be replicated

def proxy():
    # replace url with that of the real keystone
    spliturl=list(urlsplit(request.url))
    spliturl[0] = 'https'  # the real keystone is most likely behind SSL
    spliturl[1] = REAL_KEYSTONE
    url = urlunsplit(spliturl)

    # do the request
    resp = requests.request(
        method=request.method,
	#url=request.url.replace(FAKE_KEYSTONE, REAL_KEYSTONE),
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
@app.route('/v3/auth/tokens', methods=['POST'])
def v3tokens():
    # parse request
    body = flask.request.get_json()
    headers = flask.request.headers

    # Bypass requests without a password inside (e.g. for unscoped-to-scoped auth)
    if 'password' not in body['auth']['identity']:
        return proxy()
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
    sess = session.Session(auth=auth)
    token = sess.get_token()

    # patch original body
    del(body['auth']['identity'])
    body['auth']['identity'] = {"methods": ["token"],
                                "token": {"id": token}}

    # get scoped token
    r = requests.post('https://'+REAL_KEYSTONE+'/v3/auth/tokens', json=body, headers=headers)

    # forward response
    return flask.Response(r.text, headers=dict(r.headers), status=r.status_code)


#===============================================================================
@app.route('/v2.0/tokens', methods=['POST'])
def v2tokens():
    # parse request
    body = flask.request.get_json()
    headers = flask.request.headers

    # Bypass requests without a password inside (e.g. for unscoped-to-scoped auth)
    if 'passwordCredentials' not in body['auth']:
        return proxy()
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
                           project_id=tenantId,
                           project_name=tenantName,
                           project_domain_name=tenantDomain,
                           username=username,
                           password=password)
    sess = session.Session(auth=auth)
    token = sess.get_token()
    if isScoped: 
        tenantID=sess.get_project_id()

    # create new body to get the catalog without the password
    newbody = {}
    newbody['auth'] = {}
    #for key in body['auth'].keys():
    #    if key not in 'passwordCredentials':
    #        newbody['auth'][key] = body['auth'][key]
    newbody['auth']['token'] = {}
    newbody['auth']['token']['id'] = token
    if isScoped:
        # Otherwise we get an empty service catalog and nothing works
        newbody['auth']['tenantId'] = tenantID

    # resubmit request
    r = requests.post('https://'+REAL_KEYSTONE+'/v2.0/tokens', json=newbody, headers=headers)

    # forward response
    return flask.Response(r.text, headers=dict(r.headers), status=r.status_code)


# Do we need to implement / forward entire keystone API? Let's hope this is enough:
# https://developer.openstack.org/api-ref/identity/v3/
#===============================================================================
@app.route('/<path:url>')
def other(url):
    return proxy()

# TODO: do we need to patch service catalog? Let's hope not!

#===============================================================================
if __name__ == "__main__":
    if enable_ssl:
        #app.run(host='0.0.0.0', port=13000, ssl_context=('yourserver.crt', 'yourserver.key'), debug=True)
        app.run(host='0.0.0.0', port=13000, ssl_context='adhoc', debug=True)
    else:
        app.run(host='0.0.0.0', port=13000, debug=True)
#EOF
