# File: adldapcc_connector.py
#
# Copyright (c) 2023 Yassine Ben Alaya.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
# Phantom App imports
import json
import os
import ssl
import sys

# switched from python-ldap to ldap3 for this app. -gsh
import ldap3
import ldap3.extend.microsoft.addMembersToGroups
import ldap3.extend.microsoft.removeMembersFromGroups
import ldap3.extend.microsoft.unlockAccount
import phantom.app as phantom
from ldap3 import Tls
# from ldap3.utils.dn import parse_dn
from phantom.action_result import ActionResult
# import json
from phantom.base_connector import BaseConnector
from phantom_common import paths
from adldap_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class AdLdapConnector(BaseConnector):

    def __init__(self):
        super(AdLdapConnector, self).__init__()

    def replace_null_values(self, data):
        return json.loads(json.dumps(data).replace('\\u0000', '\\\\u0000'))

    def _dump_error_log(self, error, message="Exception occurred."):
        self.error_print(message, dump_object=error)

    def _ldap_bind_custom(self, param, action_result=None):
        """
        returns phantom.APP_SUCCESS if connection succeeded,
        else phantom.APP_ERROR.

        If an action_result is passed in, method will
        appropriately use it. Otherwise just return
        APP_SUCCESS/APP_ERROR
        """
        """
        if self._ldap_connection and \
                self._ldap_connection.bound and \
                not self._ldap_connection.closed:
            return True
        elif self._ldap_connection is not None:
            self._ldap_connection.unbind()

        """
        self.save_progress("_ldap_bind_custom called")
        try:
            if self._validate_ssl_cert:
                tls = Tls(ca_certs_file=paths.CA_CERTS_PEM, validate=ssl.CERT_REQUIRED)
            else:
                tls = Tls(validate=ssl.CERT_NONE)

            conf_use_ssl = True
            conf_user = param["username"]
            conf_password = param["password"]
            conf_port = param["port"]
            conf_host = param["domain"]

            server_param = {
                "use_ssl": conf_use_ssl,
                "port": conf_port,
                "host": conf_host,
                "get_info": ldap3.ALL,
                "tls": tls
            }
            self._ldap_server = ldap3.Server(**server_param)
            self._ldap_connection = ldap3.Connection(self._ldap_server,
                                                     user=conf_user,
                                                     password=conf_password,
                                                     raise_exceptions=True)
            self.save_progress("binding to directory...")

            if not self._ldap_connection.bind():
                if action_result:
                    return action_result.set_status(
                        phantom.APP_ERROR,
                        self._ldap_connection.result['description']
                    )
                else:
                    return phantom.APP_ERROR
            if action_result:
                self.save_progress("connection successfull...")
                self._ldap_connection.unbind()
                self.save_progress("unbinding successfull...")
                self.save_progress("Success: Correct credentials")
                action_result.add_data({"login_status": True})
                return action_result.set_status(phantom.APP_SUCCESS)
            else:
                return phantom.APP_SUCCESS

        except Exception as e:
            self.debug_print("[DEBUG] ldap_bind, e = {}".format(str(e)))
            if ("invalidCredentials" in str(e)):
                self.save_progress("Failed: Wrong credentials")
                action_result.add_data({"login_status": False})
                return action_result.set_status(phantom.APP_SUCCESS)
            else:
                self.save_progress("Something went wrong !")
                self._dump_error_log(e)
            if action_result:
                return action_result.set_status(
                    phantom.APP_ERROR, str(e))
            else:
                return phantom.APP_ERROR

    def _handle_test_credentials(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        # summary = action_result.update_summary({})
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        self.save_progress("_handle_test_credentials")
        # failure
        self.debug_print("pew pew")
        if not self._ldap_bind_custom(param, action_result):
            self.debug_print(str(action_result.get_status()))
            return action_result.get_status()
        # success
        self.save_progress(str(phantom.APP_SUCCESS))
        self.debug_print(str(action_result.get_status()))
        self.debug_print(str(action_result.get_status()))
        return action_result.get_status()

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        action_id = self.get_action_identifier()
        self.debug_print("ADLDAPENV = {}".format(os.environ))
        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_credentials':
            ret_val = self._handle_test_credentials(param)
            # self.save_progress(str(ret_val))

        action_results = self.get_action_results()
        # self.save_progress(action_result)
        # action_result = action_results[-1]
        # self.save_progress(action_result.get_status())
        # action_result = action_result
        # self.save_progress("Debug connector output")
        # self.save_progress(action_result)
        # try:
        #     if 'action_result' in locals():
        #         self.save_progress("Debug connector output")
        #         self.save_progress(action_result)
        # except Exception as e:
        #     self.save_progress("Error:" + str(e))
        # self.debug_print(self.save_progress(action_result))
        # action_result = action_results[-1]
        self.save_progress("Save progress")
        # self.send_progress(action_result)
        self.debug_print("before len(action_results) > 0")
        self.debug_print(len(action_results))
        # self.debug_print(json.dumps(action_results))
        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()
        if not isinstance(self._state, dict):
            self.debug_print("Resetting the state file with the default format")
            self._state = {
                "app_version": self.get_app_json().get('app_version')
            }

        # get the asset config
        # config = self.get_config()

        # load our config for use.
        # self._server = config['server']
        # self._username = config['username']
        # self._password = config['password']
        # self._ssl = config['force_ssl']
        # self._validate_ssl_cert = config['validate_ssl_cert']
        self._validate_ssl_cert = False
        # self._ssl_port = int(config['ssl_port'])
        self.connected = False
        self._ldap_connection = None

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':
    import argparse

    import pudb
    import requests

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)
    argparser.add_argument('-v', '--verify', action='store_true', help='verify', required=False, default=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            login_url = AdLdapConnector._get_phantom_base_url() + 'login'

            print("Accessing the Login page")
            r = requests.get(login_url, verify=verify, timeout=DEFAULT_TIMEOUT)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=verify, data=data, headers=headers, timeout=DEFAULT_TIMEOUT)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            sys.exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = AdLdapConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
