from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.gikuluca.landscape.plugins.module_utils.base import API, HTTPError

DOCUMENTATION = """
module: landscape_get
short_description: Ubuntu Landscape Get Functions
version_added: 2.12.0
author: LUCA Gheorghe (@gikuluca) 

description:
    - Get Landscape api functions

options:
    landscape_url:
        description:
            - Landscape api URL ex: https://landscape.ubuntu.com/api
        type: str
        required: true
    landscape_key:
        description:
            - Landscape api key used to authenticate to the API
        type: str 
        required: true
    landscape_secret:
        description:
            - Landscape secret used to authenticate to the API
        type: str
        required: true
    landscape_ca_path:
        description:
            - If you are using a custom Certificate Authority (CA), you will also need to tell the API tool where to find that certificate
        type: str
        required: false
        default: None
    function:
        description:
            - The name of the api function you need
        type: str
        required: true
        choices: ['get_activities', 'get_activity_types', 'get_alert_subscribers', 'get_alerts',
                                       'get_administrators', 'get_computers', 'get_gpg_keys', 'get_packages',
                                       'get_package_profiles', 'get_removal_profiles', 'get_distributions',
                                       'get_apt_sources', 'get_access_groups', 'get_permissions', 'get_roles',
                                       'get_event_log'])
    query:
        description:
            - A query string with space separated tokens used to filter
        type: str
        required: false
        default: ''
"""
EXAMPLES = """
- name: Example
  gikuluca.landscape.landscape_get:
    landscape_url: https://landscape.local.com/api/
    landscape_key: my_api_key
    landscape_secret: my_api_secret
    function: get_computers
"""
RETURN = """
"""


class LandscapeApiGet:
    def __init__(self):
        self.module = AnsibleModule(
            argument_spec=dict(
                landscape_url=dict(required=True, type='str'),
                landscape_key=dict(required=True, type='str'),
                landscape_secret=dict(required=True, type='str'),
                landscape_ca_path=dict(required=False, type='str', default=None),
                function=dict(required=True, type='str',
                              choices=['get_activities', 'get_activity_types', 'get_alert_subscribers', 'get_alerts',
                                       'get_administrators', 'get_computers', 'get_gpg_keys', 'get_packages',
                                       'get_package_profiles', 'get_removal_profiles', 'get_distributions',
                                       'get_apt_sources', 'get_access_groups', 'get_permissions', 'get_roles',
                                       'get_event_log']),
                # query=dict(required=False, type='str', default=None)
            )
        )
        self.landscape_url = self.module.params.get('landscape_url')
        self.landscape_key = self.module.params.get('landscape_key')
        self.landscape_secret = self.module.params.get('landscape_secret')
        self.landscape_ca = self.module.params.get('landscape_ca_path')
        self.functions_local = self.module.params.get('function')
        # self.query = self.module.params.get('query')

        self.result = None


def main():
    lsc = LandscapeApiGet()

    api = API(lsc.landscape_url, lsc.landscape_key, lsc.landscape_secret, lsc.landscape_ca)
    try:
        lsc.result = eval('api.%s()' % (lsc.functions_local))#, lsc.query))
    except HTTPError as e:
        lsc.module.fail_json("\nGot server error:\n"
                             "Code: %d\n"
                             "Message: %s\n" % (e.code, e.message))

    lsc.module.exit_json(changed=False, resultat=lsc.result)


if __name__ == '__main__':
    main()
