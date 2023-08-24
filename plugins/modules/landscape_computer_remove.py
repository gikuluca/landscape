from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.gikuluca.landscape.plugins.module_utils.base import API, HTTPError

DOCUMENTATION = """
module: landscape_computer_remove
short_description: Ubuntu Landscape remove computer
version_added: 2.12.0
author: LUCA Gheorghe (@gikuluca) 

description:
    - Delete Landscape  computer api 

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
    computer_name:
        description:
            - The computer name 
        type: str
        required: true
"""
EXAMPLES = """
- name: Example delete computer
  gikuluca.landscape.landscape_computer:
    landscape_url: https://landscape.local.com/api/
    landscape_key: my_api_key
    landscape_secret: my_api_secret
    computer_name: my_computer
"""
RETURN = """
"""


class LandscapeComputerRemove:
    def __init__(self):
        self.module = AnsibleModule(
            argument_spec=dict(
                landscape_url=dict(required=True, type='str'),
                landscape_key=dict(required=True, type='str'),
                landscape_secret=dict(required=True, type='str'),
                landscape_ca_path=dict(required=False, type='str', default=None),
                computer_name=dict(required=True, type='str')
            )
        )
        self.landscape_url = self.module.params.get('landscape_url')
        self.landscape_key = self.module.params.get('landscape_key')
        self.landscape_secret = self.module.params.get('landscape_secret')
        self.landscape_ca = self.module.params.get('landscape_ca_path')
        self.computer_name = self.module.params.get('computer_name')

        self.result = {
            'changed': False,
            'response': ''
        }
        self.API_landscape = API(self.landscape_url, self.landscape_key, self.landscape_secret, self.landscape_ca)

    def get_computers(self):
        result = []
        try:
            result = self.API_landscape.get_computers()
        except HTTPError as e:
            self.module.fail_json("\nGot server error:\n"
                                  "Code: %d\n"
                                  "Message: %s\n" % (e.code, e.message))
        return result

    def check_state(self, computers):
        return True if self.computer_name in computers else False

    def get_computer_id(self, computers):
        return_id = -1
        for computer in computers:
            if computer['hostname'] in self.computer_name:
                return_id = computer['id']
        return return_id

    def delete_computer(self, computer_id):
        try:
            self.API_landscape.remove_computers(computer_ids=[computer_id])
        except HTTPError as e:
            self.module.fail_json("\nGot server error:\n"
                                  "Code: %d\n"
                                  "Message: %s\n" % (e.code, e.message))


def main():
    lsc = LandscapeComputerRemove()
    computers = lsc.get_computers()
    actual_computers = list(map(lambda x: x['hostname'], computers))
    lsc.result['changed'] = lsc.check_state(actual_computers)
    if lsc.result['changed']:
        computer_id = lsc.get_computer_id(computers)
        lsc.delete_computer(computer_id)
    else:
        lsc.result['response'] = 'No computer deleted'
    lsc.module.exit_json(**lsc.result)


if __name__ == '__main__':
    main()
