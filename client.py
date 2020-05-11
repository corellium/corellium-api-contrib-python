#!/usr/bin/env python3

import datetime
import getpass
import logging
import requests
import time
import urllib.parse
import urllib3.exceptions
import uuid
import warnings

logger = logging.getLogger('Corellium')

# this is a partial python api inspired by the js one found at:
# https://github.com/corellium/corellium-api

class Client(object):
    def __init__(self, endpoint):
        self.endpoint = urllib.parse.urljoin(endpoint, '/api/v1')
        self.username = None
        self.password = None
        self.token = None
        self.uuid = uuid.uuid4()
        self.session = requests.Session()

    @classmethod
    def from_client(cls, original):
        new_client = cls(original.endpoint)
        new_client.__dict__.update(original.__dict__)
        new_client.session = requests.Session()
        new_client.session.headers['Authorization'] = new_client.token['token']
        return new_client

    def fetch(self, url, data=None, method=None, raw=False):
        if self.token:
            if self.token['expiration'] <= int(time.time()):
                self.token = None
                self.login()

        if method:
            method = getattr(self.session, method.lower())
        else:
            method = self.session.post if data else self.session.get

        logger.debug(
            'method: {} url: {}{} data: {} headers: {}'.format(
                method.__name__.upper(), self.endpoint, url, data, self.session.headers
            )
        )
        while True:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', urllib3.exceptions.InsecureRequestWarning)
                try:
                    res = method(
                        '{}{}'.format(self.endpoint, url), json=data, verify=False
                    )
                except TimeoutError:
                    time.sleep(10)
                    continue

            if res.status_code == 429:
                retryAfter = res.headers.get('retry-after')
                print('server told us to try again after {} seconds'.format(retryAfter))
                time.sleep(int(retryAfter))
                continue

            logger.debug(
                'response: code: {} content: {}'.format(
                    res.status_code, res.content.decode('utf-8')
                )
            )
            if raw:
                return res.content

            if res.content:
                return res.json()
            return {}

    def login(self):
        if not self.username or not self.password:
            self.username = input('Corellium Username [admin]:').strip()
            if not self.username:
                self.username = 'admin'
            self.password = getpass.getpass('Corellium Password: ')

        if not self.token:
            js = self.fetch(
                '/tokens', data={'username': self.username, 'password': self.password}
            )
            if 'token' not in js or 'expiration' not in js:
                raise ValueError('Login failed!')

            # TODO there must be a better way to do this, but I don't know what it is
            expiration = int(
                datetime.datetime.strptime(
                    js['expiration'], '%Y-%m-%dT%H:%M:%S.000Z'
                ).timestamp()
            )
            # expiration is in UTC, we aren't
            expiration -= (datetime.datetime.utcnow() - datetime.datetime.now()).seconds
            self.token = {'token': js['token'], 'expiration': expiration}
            self.session.headers['Authorization'] = js['token']

        return self.token

    def get_projects(self):
        project_dicts = self.fetch('/projects')
        if 'error' in project_dicts:
            print('error:', project_dicts['error'])
            return []
        return [Project(self, **p_dict) for p_dict in project_dicts]

    def create_project(self, name, color=1, version=1, internet=True):
        res = self.fetch(
            '/projects',
            method='post',
            data={
                'name': name,
                'color': color,
                'settings': {'version': version, 'internet-access': internet},
            },
        )
        return self.get_project(res['id'])

    def get_project(self, project_id):
        project_dict = self.fetch('/projects/{}'.format(project_id))
        return Project(self, **project_dict)

    def get_instance(self, instance_id):
        instance_dict = self.fetch('/instances/{}'.format(instance_id))
        return Instance(self, instance_dict)

    def get_supported(self):
        return self.fetch('/supported')

    def get_supported_flavors(self, os_type=None):
        if os_type:
            return [
                entry['flavor']
                for entry in self.get_supported()
                if entry['type'] == os_type
            ]
        return [entry['flavor'] for entry in self.get_supported()]

    def get_supported_oses(self, flavor):
        for entry in self.get_supported():
            if entry['flavor'] == flavor:
                return [fw['version'] for fw in entry['firmwares']]
        return []


class Project(object):
    def __init__(self, client, **kwargs):
        self.client = client
        for attr, val in kwargs.items():
            setattr(self, attr, val)

    def fetch(self, url, **kwargs):
        return self.client.fetch('/projects/{}{}'.format(self.id, url), **kwargs)

    def create_instance(self, flavor, os, name=''):
        instance_id_dict = self.client.fetch(
            '/instances',
            method='post',
            data={'project': self.id, 'flavor': flavor, 'os': os, 'name': name},
        )
        return self.get_instance(instance_id_dict['id'])

    def get_instance(self, instance_id):
        instance_dict = self.client.fetch('/instances/{}'.format(instance_id))
        return Instance(self.client, instance_dict)

    def get_instances(self):
        instance_dicts = sorted(
            self.fetch('/instances'), key=lambda instance_dict: instance_dict['created']
        )
        return [
            Instance(self.client, instance_dict) for instance_dict in instance_dicts
        ]

    def get_vpn_config(self):
        return self.fetch(
            '/vpn-configs/{}.ovpn'.format(str(self.client.uuid)), raw=True
        )

    def delete_project(self):
        self.fetch('', method='delete')

    def set_quota(self, cores):
        return self.fetch('', method='patch', data={'quotas': {'cores': cores}})


class Instance(object):
    def __init__(self, client, info):
        self.client = client
        self.info = info
        for attr, val in info.items():
            setattr(self, attr, val)

    def fetch(self, url, **kwargs):
        return self.client.fetch('/instances/{}{}'.format(self.id, url), **kwargs)

    def delete_instance(self):
        return self.fetch('', method='delete')

    def get_instance(self):
        return self.fetch('')

    def get_panics(self):
        return self.fetch('/panics')

    def clear_panics(self):
        return self.fetch('/panics', method='delete')

    def get_console_log(self):
        return self.fetch('/consoleLog', raw=True).decode('utf8')

    def reboot(self):
        return self.fetch('/reboot', method='post')

    def update(self):
        self.info = self.fetch('')

    def is_creation_done(self):
        return self.info['state'] != 'creating'

    def wait_for_creation_done(self):
        self.update()
        while not self.is_creation_done():
            time.sleep(5)
            self.update()
