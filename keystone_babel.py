#!/usr/bin/env python
# -*- coding: utf-8 -*-


import flask
import requests

from keystoneauth1.extras._saml2 import V3Saml2Password
from keystoneauth1.identity.v3 import Token
from keystoneauth1 import session

app = flask.Flask(__name__)

REAL_KEYSTONE = 'https://pollux-tds.cscs.ch:13000'
OS_AUTH_URL = 'https://pollux-tds.cscs.ch:13000/v3'
OS_IDENTITY_PROVIDER = 'cscskc'
OS_IDENTITY_PROVIDER_URL = 'https://kc-tds.cscs.ch/auth/realms/cscs/protocol/saml/'
OS_PROTOCOL = 'mapped'
OS_INTERFACE = 'public'

# TODO implement / forward entire keystone API
# https://developer.openstack.org/api-ref/identity/v3/


#===============================================================================
@app.route('/v3/auth/tokens', methods=['POST'])
def tokens():
    print "Requested %s: %s", flask.request.method, '/v3/auth/tokens'
    # parse request
    body = flask.request.get_json()
    headers = flask.request.headers
    print "Body: ", body
    print "Headers: ", headers
    # Bypass requests without a password inside (e.g. for unscoped-to-scoped auth)
    if 'password' not in body['auth']['identity']:
        print "proxying the non-password request to the real keystone"
        #r = requests.post(REAL_KEYSTONE+"/v3/auth/token", json=body, headers={'X-Auth-Token':headers['X-Auth-Token']})
        r = requests.post(REAL_KEYSTONE+"/v3/auth/token", json=body, headers=headers)
        print "Response: ", r.status_code, r.headers, r.text
        return flask.Response(r.text, headers=dict(r.headers), status=r.status_code)
        #print "redirecting to: "+REAL_KEYSTONE+"/v3/auth/token"
        #return flask.redirect (REAL_KEYSTONE+"/v3/auth/token")
    user = body['auth']['identity']['password']['user']
    username = user['name']
    password = user['password']

    # get unscoped token via SAML
    auth = V3Saml2Password(auth_url=OS_AUTH_URL,
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
    r = requests.post(OS_AUTH_URL+'/auth/tokens', json=body, headers=headers)

    print "Response: ", r.status_code, r.headers, r.text
    
    # TODO: maybe patch service catalog?

    # forward response
    return flask.Response(r.text, headers=dict(r.headers), status=r.status_code)

#===============================================================================
@app.route('/<path:url>', methods=['POST','GET'])
def other(url):
    print "Requested %s: %s", flask.request.method, url
    body = flask.request.get_json()
    headers = flask.request.headers
    print "Body: ", body
    print "Headers: ", headers
#    body = flask.request.get_json()
#    app.logger.info("Body %s", body)
#    if flask.request.method == 'POST':
#      r = requests.post(REAL_KEYSTONE+url, json=body)
#    else:
#      app.logger.info("Redirecting to: %s", OS_AUTH_URL+url)
#      return flask.redirect (REAL_KEYSTONE+url)
#      app.logger.info("Args %s", flask.request.args)
#      app.logger.info("Headers %s", flask.request.headers)
#      req_url = OS_AUTH_URL+"/{}?{}".format(url, flask.request.query_string.decode('utf-8'))
#      app.logger.info("Target %s", req_url)
#      r = requests.get(req_url, headers=flask.request.headers, stream=True)
#    return flask.Response(r.text, headers=dict(r.headers), status=r.status_code)
    return flask.redirect (REAL_KEYSTONE+'/'+url)

#===============================================================================
if __name__ == "__main__":
    app.run(port=13000, debug=True)

#EOF
