import flask
from xmltodict import parse
from flask import current_app
from .cas_urls import create_cas_login_url
from .cas_urls import create_cas_logout_url
from .cas_urls import create_cas_validate_url

try:
    from urllib import urlopen
except ImportError:
    from urllib.request import urlopen

import hashlib
import pprint

blueprint = flask.Blueprint('cas', __name__)


@blueprint.route('/login/')
def login():
    """
    This route has two purposes. First, it is used by the user
    to login. Second, it is used by the CAS to respond with the
    `ticket` after the user logs in successfully.

    When the user accesses this url, they are redirected to the CAS
    to login. If the login was successful, the CAS will respond to this
    route with the ticket in the url. The ticket is then validated.
    If validation was successful the logged in username is saved in
    the user's session under the key `CAS_USERNAME_SESSION_KEY` and
    the user's attributes are saved under the key
    'CAS_USERNAME_ATTRIBUTE_KEY'
    """

    cas_token_session_key = current_app.config['CAS_TOKEN_SESSION_KEY']

    redirect_url = create_cas_login_url(
        current_app.config['CAS_SERVER'],
        current_app.config['CAS_LOGIN_ROUTE'],
        flask.url_for('.login', _external=True))

    if 'ticket' in flask.request.args:
        flask.session[cas_token_session_key] = flask.request.args['ticket']

    if cas_token_session_key in flask.session:

        if validate(flask.session[cas_token_session_key]):
            if 'CAS_AFTER_LOGIN_SESSION_URL' in flask.session:
                redirect_url = flask.session.pop('CAS_AFTER_LOGIN_SESSION_URL')
            else:
                redirect_url = flask.url_for(
                    current_app.config['CAS_AFTER_LOGIN'])
        else:
            del flask.session[cas_token_session_key]

    current_app.logger.debug('Redirecting to: {0}'.format(redirect_url))

    return flask.redirect(redirect_url)


@blueprint.route('/logout/')
def logout():
    """
    When the user accesses this route they are logged out.
    """

    cas_username_session_key = current_app.config['CAS_USERNAME_SESSION_KEY']
    cas_attributes_session_key = current_app.config['CAS_ATTRIBUTES_SESSION_KEY']

    try:
        pp = pprint.PrettyPrinter(indent=0)
        current_app.logger.info("User logged out: %s" % (pp.pformat(flask.session[cas_attributes_session_key]).replace("\n", " "),))
    except:
        pass

    if cas_username_session_key in flask.session:
        del flask.session[cas_username_session_key]

    if cas_attributes_session_key in flask.session:
        del flask.session[cas_attributes_session_key]

    if(current_app.config['CAS_AFTER_LOGOUT'] != None):
        redirect_url = create_cas_logout_url(
            current_app.config['CAS_SERVER'],
            current_app.config['CAS_LOGOUT_ROUTE'],
            current_app.config['CAS_AFTER_LOGOUT'])
    else:
        redirect_url = create_cas_logout_url(
            current_app.config['CAS_SERVER'],
            current_app.config['CAS_LOGOUT_ROUTE'])

    current_app.logger.debug('Redirecting to: {0}'.format(redirect_url))
    return flask.redirect(redirect_url)


def validate(ticket):
    """
    Will attempt to validate the ticket. If validation fails, then False
    is returned. If validation is successful, then True is returned
    and the validated username is saved in the session under the
    key `CAS_USERNAME_SESSION_KEY` while tha validated attributes dictionary
    is saved under the key 'CAS_ATTRIBUTES_SESSION_KEY'.
    """

    cas_username_session_key = current_app.config['CAS_USERNAME_SESSION_KEY']
    cas_attributes_session_key = current_app.config['CAS_ATTRIBUTES_SESSION_KEY']

    current_app.logger.debug("validating token {0}".format(ticket))

    cas_validate_url = create_cas_validate_url(
        current_app.config['CAS_SERVER'],
        current_app.config['CAS_VALIDATE_ROUTE'],
        flask.url_for('.login', _external=True),
        ticket)

    current_app.logger.debug("Making GET request to {0}".format(
        cas_validate_url))

    xml_from_dict = {}
    isValid = False

    try:
        xmldump = urlopen(cas_validate_url).read().strip().decode('utf8', 'ignore')
        xml_from_dict = parse(xmldump)
        isValid = True if "cas:authenticationSuccess" in xml_from_dict["cas:serviceResponse"] else False
    except ValueError:
        current_app.logger.error("CAS returned unexpected result")

    if isValid:
        current_app.logger.debug("valid")
        xml_from_dict = xml_from_dict["cas:serviceResponse"]["cas:authenticationSuccess"]
        username = xml_from_dict["cas:user"]
        attributes = {}
        try:
            attributes.update(xml_from_dict["cas:attributes"])
        except:
            pass

        try:
            attributes.update({
                "dash:person_id": dash_md5(attributes['cas:harvardEduIdNumber']),
                "dash:person_id_source": "huid"
            })
            del attributes['cas:harvardEduIdNumber']
        except:
            try:
                attributes.update({
                    "dash:person_id": dash_md5(attributes['cas:eduPersonPrincipalName']),
                    "dash:person_id_source": "eppn"
                })
            except:
                current_app.logger.warning("Could not generate person ID from HUID or EPPN -- using %s %s" % (attributes['cas:authenticationType'], username))
                attributes.update({
                    "dash:person_id": dash_md5(username),
                    "dash:person_id_source": "username:%s" % (attributes['cas:authenticationType'],)
                })

        if "cas:memberOf" in attributes:
            attributes["cas:memberOf"] = attributes["cas:memberOf"].lstrip('[').rstrip(']').split(',')
            for group_number in range(0, len(attributes['cas:memberOf'])):
                attributes['cas:memberOf'][group_number] = attributes['cas:memberOf'][group_number].lstrip(' ').rstrip(' ')

        # I think we never use this
        flask.session[cas_username_session_key] = username
        flask.session[cas_attributes_session_key] = attributes

        pp = pprint.PrettyPrinter(indent=0)
        current_app.logger.info("User logged in: %s" % (pp.pformat(attributes).replace("\n", " "),))
    else:
        current_app.logger.debug("invalid")

    return isValid

def dash_md5(username):
    if isinstance(username, str):
        username = username.encode('utf-8')
    m = hashlib.md5()
    m.update(username)
    m.update(current_app.config['DASH_SALT'])
    return m.hexdigest()
