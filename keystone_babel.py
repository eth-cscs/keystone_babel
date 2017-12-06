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
enable_ssl = False

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
def tokens():
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
    unscoped_token = sess.get_token()

    # patch original body
    del(body['auth']['identity'])
    body['auth']['identity'] = {"methods": ["token"],
                                "token": {"id": unscoped_token}}

    # get scoped token
    r = requests.post('https://'+REAL_KEYSTONE+'/v3/auth/tokens', json=body, headers=headers)

    # forward response
    return flask.Response(r.text, headers=dict(r.headers), status=r.status_code)

# Do we need to implement / forward entire keystone API? Let's hope this is enough:
# https://developer.openstack.org/api-ref/identity/v3/
#===============================================================================
@app.route('/<path:url>', methods=['POST','GET'])
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
