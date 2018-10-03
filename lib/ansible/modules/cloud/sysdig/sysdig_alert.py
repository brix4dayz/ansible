#!/usr/bin/python

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: sysdig_alert

short_description: A module to provision alerts in SysDig.

version_added: "2.6"

description:
    - TODO

options:

    name:
        description:
            - TODO
        required: true

    condition:
        description:
            - TODO
        required: true

    evaluation_period:
        description:
            - TODO
        required: true

    notification_channels:
        description:
            - TODO
        required: true

    enabled:
        description:
            - TODO
        required: false

    severity:
        description:
            - TODO
        required: false

    state:
        description:
            - TODO
        required: false

    segment:
        by:
        condition:

    user_filter:
        description:
            - TODO
        required: true

    description:
        description:
            - TODO
        required: false

    annotations:
        description:
            - TODO
        required: false

extends_documentation_fragment:
    - sysdig

author:
    - Hayden Fuss (@brix4dayz)
'''

EXAMPLES = '''
# Pass in a message
- name: Test with a message
  my_new_test_module:
    name: hello world

# pass in a message and have changed true
- name: Test with a message and changed output
  my_new_test_module:
    name: hello world
    new: true

# fail the module
- name: Test failure of the module
  my_new_test_module:
    name: fail me
'''

RETURN = '''
original_message:
    description: The original name param that was passed in
    type: str
message:
    description: The output message that the sample module generates
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url
from urllib2 import HTTPError
import json


class SysDigException(Exception):

    def __init__(self, error, msg):
        self.error = error
        self.msg = msg


class SysDigClientException(SysDigException):
    def __init__(self, error, msg, status_code, url, http_msg):
        super(SysDigClientException, self).__init__(error=error, msg=msg)
        self.status_code = status_code
        self.http_msg = http_msg
        self.url = url


class SysDigClient:

    DEFAULT_URL = 'https://app.sysdigcloud.com'

    def __init__(self, token, url):
        self.token = token
        self.url = url
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            # 'Accept-Encoding': 'gzip, deflate, sdch',
            'Authorization': 'Bearer %s' % self.token
        }

    def get_by_id(self, resource, sysdig_id):
        resp = open_url(
            url='%s/api/%ss/%s' % (self.url, resource, sysdig_id),
            method='GET',
            headers=self.headers
        )
        resp_json = json.loads(resp.read())
        return resp_json[resource]

    def get_by_name(self, resource, name):
        resource_instances = self.list(resource)
        for resource_instance in resource_instances:
            if 'name' in resource_instance and resource_instance['name'] == name:
                return resource_instance
        return None  # TODO raise exception ?

    def list(self, resource):
        resp = open_url(
            url='%s/api/%ss' % (self.url, resource),
            method='GET',
            headers=self.headers
        )
        # TODO check status code
        resp_json = json.loads(resp.read())
        return resp_json['%ss' % resource]

    def update(self, resource, sysdig_id, data):
        json_data = dict()
        json_data[resource] = data
        try:
            resp = open_url(
                url='%s/api/%ss/%s' % (self.url, resource, sysdig_id),
                method='PUT',
                headers=self.headers,
                data=json.dumps(json_data)
            )
            resp_json = json.loads(resp.read())
            return resp_json, resp_json['%s' % resource]
        except HTTPError as err:
            raise SysDigClientException(error="failed_update",
                                        msg="Failed to update resource '%s'" % resource,
                                        status_code=err.code,
                                        url=err.url,
                                        http_msg=err.msg)

    def delete(self, resource, sysdig_id):
        resp = open_url(
            url='%s/api/%ss/%s' % (self.url, resource, sysdig_id),
            method='DELETE',
            headers=self.headers
        )
        return
        # # TODO check status code
        # return True

    def create(self, resource, data):
        json_data = dict()
        json_data[resource] = data
        json_data = json.dumps(json_data)

        resp = open_url(
            url='%s/api/%ss' % (self.url, resource),
            method='POST',
            headers=self.headers,
            data=json_data
        )
        # TODO check status code
        resp_json = json.loads(resp.read())
        return resp_json, resp_json['%s' % resource]


class SysDigObject(object):

    STATE_PRESENT = 'present'
    STATE_ABSENT = 'absent'
    ALLOWED_STATES = (STATE_PRESENT, STATE_ABSENT)

    def __init__(self, client, data):
        if client.__class__ is not SysDigClient:
            raise SysDigException(error="invalid_client",
                                  msg="SysDigObject.client that is not an instance of SysDigClient.")

        self.client = client

        if 'state' not in data:
            data['state'] = SysDigObject.STATE_PRESENT

        if data['state'] not in self.__class__.ALLOWED_STATES:
            raise SysDigException(error="invalid_state",
                                  msg="State must be one of the following: %s" % str(SysDigObject.ALLOWED_STATES))
        self.state = data['state']

        if 'id' in data and data['id'] is not None:
            self.id, self.obj = self._get_by_id(sysdig_id=data['id'])
        elif 'name' in data:
            self.id, self.obj = self._get_by_name(name=data['name'])
        else:
            raise SysDigException(error="missing_identifier",
                                  msg="'name' must be provided, 'id' is optional and improves performance.")
        self.exists = self.id is not None

        self._validate(data=data)
        self.data = self._adapt(data=data)

        if self.exists:
            self.data['id'] = self.id
            self.data['version'] = self.obj['version']


    @property
    def resource(self):
        raise NotImplementedError

    def _validate(self, data):
        raise NotImplementedError

    def _adapt(self, data):
        raise NotImplementedError

    def _get_by_id(self, sysdig_id):
        _result = self.client.get_by_id(self.resource, sysdig_id)
        return (_result['id'], _result) if _result is not None else (None, None)

    def _get_by_name(self, name):
        _result = self.client.get_by_name(self.resource, name)
        return (_result['id'], _result) if _result is not None else (None, None)

    def create(self):
        if self.exists:
            raise SysDigException(error="resource_already_exists",
                                  msg="Cannot create resource because it already exists.")
        _response, _result = self.client.create(self.resource, self.data)
        self.id = _result['id']
        self.exists = True
        return _response

    def update(self):
        _response, _result = self.client.update(self.resource, self.id, self.data)
        return _response

    def delete(self):
        if not self.exists:
            return None  # TODO return result that signals unchanged
        _response = self.client.delete(self.resource, self.id)
        self.id = None
        self.exists = False
        return _response

    def sync(self):
        if self.state == self.__class__.STATE_ABSENT:
            return self.delete()
        elif self.state == self.__class__.STATE_PRESENT and self.exists:
            return self.update()
        else:
            return self.create()


class SysDigAlert(SysDigObject):

    SEVERITY_MAPPER = {
        'debug': 7,
        'info': 6,
        'notice': 5,
        'warning': 4,
        'error': 3,
        'critical': 2,
        'alert': 1,
        'emergency': 0
    }

    @property
    def resource(self):
        return 'alert'

    def _validate(self, data):
        pass  # TODO

    def _adapt(self, data):
        self.notification_channels = []
        for notification_channel_data in data['notification_channels']:
            notification_channel = SysDigNotificationChannel(client=self.client,
                                                             data=notification_channel_data)
            notification_channel.sync()  # TODO error handle
            self.notification_channels.append(notification_channel)

        obj_data = {
            'type': 'MANUAL',
            'name': data['name'],
            'description': data['description'],
            'enabled': data['enabled'],
            'severity': self.__class__.SEVERITY_MAPPER[data['severity']],
            'timespan': data['timespan'] * 1000000,
            'condition': data['condition'],
            'filter': data['filter'],
            'notificationChannelIds': [channel.id for channel in self.notification_channels if channel.exists]
        }

        # TODO fix
        if 'segement_by' in data and data['segement_by'] is not []:
            obj_data['segementBy'] = data['segment_by']
            obj_data['segmentCondition'] = {
                'type': data['segment_condition']
            }

        return obj_data


class SysDigNotificationChannel(SysDigObject):

    TYPE_OPTIONS_MAPPER = {
        'EMAIL': {
            'email_recipients': {
                'json_field': 'emailRecipients',
                'type': list
            },
            'notify_on_ok': {
                'json_field': 'notifyOnOk',
                'type': bool
            }
        },
        'SLACK': {  # FIXME: this doesn't work without somehow supplying credentials for slack
            'slack_channel': {
                'json_field': 'channel',
                'type': str
            },
            'notify_on_ok': {
                'json_field': 'notifyOnOk',
                'type': bool
            }
        },
        'SNS': {
            'sns_topic_arns': {
                'json_field': 'snsTopicARNS',
                'type': list
            },
            'notify_on_ok': {
                'json_field': 'notifyOnOk',
                'type': bool
            }
        },
        'PAGER_DUTY': {
            'account': {
                'json_field': 'account',
                'type': str
            },
            'service_name': {
                'json_field': 'serviceName',
                'type': str
            },
            'resolve_on_ok': {
                'json_field': 'resolveOnOk',
                'type': bool
            }
        }
    }

    @property
    def resource(self):
        return 'notificationChannel'

    def _validate(self, data):
        if 'type' not in data or type(data['type']) is not str:
            raise SysDigException(error="invalid_channel_type",
                                  msg="'type' must be provided and of type string.")

        if 'name' not in data or type(data['name']) is not str:
            raise SysDigException(error="invalid_channel_name",
                                  msg="'name' must be provided and of type string.")

        if 'enabled' not in data or type(data['enabled']) is not bool:
            raise SysDigException(error="invalid_channel_enabled",
                                  msg="'type' must be provided and of type bool.")
        self.channel_type = data['type'].upper()

        if self.channel_type not in self.__class__.TYPE_OPTIONS_MAPPER:
            raise SysDigException(error="invalid_channel_type",
                                  msg="'type' must be one of the following %s" % str([_type.lower() for _type in self.__class__.TYPE_OPTIONS_MAPPER.keys()]))

        # TODO Does ansible have to be compatible w/ python3?
        for ansible_field, mapper in self.__class__.TYPE_OPTIONS_MAPPER[self.channel_type].iteritems():
            if ansible_field not in data or type(data[ansible_field]) is not mapper['type']:
                raise SysDigException(error="invalid_channel_%s_%s" % (self.channel_type, ansible_field),
                                      msg="'%s' must be provided for and of type %s" % (ansible_field, mapper['type']))

        return

    def _adapt(self, data):
        obj_data = {
            'name': data['name'],
            'type': self.channel_type,
            'enabled': data['enabled'],
            'options': {}
        }

        for ansible_field, mapper in self.__class__.TYPE_OPTIONS_MAPPER[self.channel_type].iteritems():
            obj_data['options'][mapper['json_field']] = data[ansible_field]

        return obj_data


def run_module():
    # define the available arguments/parameters that a user can pass to
    # the module
    argument_spec = dict(
        name=dict(type='str', required=True),
        url=dict(type='str', default=SysDigClient.DEFAULT_URL),
        token=dict(type='str', required=True),
        condition=dict(type='str', required=True),
        timespan=dict(type='int', required=True),
        notification_channels=dict(type='list', required=True),
        state=dict(type='str', required=False, choices=SysDigObject.ALLOWED_STATES, default='present'),
        id=dict(type='str', required=False, default=None),
        enabled=dict(type='bool', required=False, default=True),
        severity=dict(type='str', required=False, choices=['emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'info', 'debug'], default='warning'),
        segment=dict(type='dict', required=False, default=None),
        filter=dict(type='str', required=False, default=None),
        description=dict(type='str', required=False, default=''),
        annotations=dict(type='dict', required=False, default={})
    )

    result = dict(
        changed=True,
        params=None,
        alert=None,
        notifcation_channels=[],
        state='present'
    )

    module = AnsibleModule(
        argument_spec=argument_spec
        # supports_check_mode=True
    )

    result['params'] = module.params

    try:
        client = SysDigClient(token=module.params['token'], url=module.params['url'])

        alert = SysDigAlert(client=client, data=module.params)
        result['response'] = alert.sync()

        result['alert'] = alert.data
        result['notificationChannels'] = [notification_channel.data for notification_channel in alert.notification_channels]
    except SysDigException as ex:
        module.fail_json(
            **ex.__dict__
        )

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
