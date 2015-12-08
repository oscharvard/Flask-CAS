import json
import ldap
import sys
import hashlib
from flask import current_app, session

ldap.set_option(ldap.OPT_DEBUG_LEVEL, 0)
# turn off referrals
ldap.set_option(ldap.OPT_REFERRALS, 0)
# version 3
ldap.set_option (ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)
# allow self-signed cert
ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

def ldap_lookup(username):
    CUSTOMER_NAME = current_app.config['CUSTOMER_NAME']
    CUSTOMER_PW = current_app.config['CUSTOMER_PW']
    LDAP_URL  = current_app.config['LDAP_URL']
    DASH_SALT = current_app.config['DASH_SALT']

    output = {}

    m = hashlib.md5()
    m.update(username)
    m.update(DASH_SALT)
    output['person_id'] = m.hexdigest()

    ad_bind_usr = 'uid=%s, ou=applications,o=Harvard University Core,dc=huid,dc=harvard,dc=edu' % CUSTOMER_NAME
    ad_bind_pw = CUSTOMER_PW

    l = ldap.initialize(LDAP_URL,trace_level=0)
    l.simple_bind_s(ad_bind_usr, ad_bind_pw)
    
    FIELDS_TO_RETURN = ['sn', 'givenName', 'displayName', 'mail']
    AD_SEARCH_DN = "ou=people, o=Harvard University Core, dc=huid, dc=harvard, dc=edu"
    search_filter = '(harvardEduIDNumber=%s)' % username
    results = l.search_ext_s(AD_SEARCH_DN,ldap.SCOPE_SUBTREE, search_filter,FIELDS_TO_RETURN)
    if results:
        try:
            cn, lu = results[0]
            for k, v in lu.iteritems():
                # take first value only?
                output[k] = v[0]
        except:
            pass

    #return json.dumps(output)
    return output

# make this look in CAS attributes for LDAP attributes
def get_ldap_attribute(attr):
    try:
        # this is wrong:
        raw_ldap_attributes = session[current_app.config['LDAP_ATTRIBUTES_SESSION_KEY']]
    except:
        return None
    ldap_attributes = json.loads(raw_ldap_attributes)
    if attr in ldap_attributes:
        return ldap_attributes[attr]
    else:
        return None
