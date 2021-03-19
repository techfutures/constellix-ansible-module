#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: constellix
short_description: Interface with Constellix DNS API.
description:
   - >
     Retrieve domain information, records within a specified domain, and update existing A records' value and TTL using the Constellix REST API. 
options:
  account_key:
    description:
      - Account API Key.
    required: true
    type: str

  account_secret:
    description:
      - Account Secret Key.
    required: true
    type: str

  domain:
    description:
      - Domain to work with. (e.g. "mydomain.com")
    required: true
    type: str

    default: 'no'

  record_name:
    description:
      - Record name to get/update. If record_name is not specified; all records for the domain will be returned in "result" regardless
        of the state argument.
    type: str

  record_value:
    description:
      - >
        Record value.
      - >
        If record_value is not specified; no changes will be made and the record will be returned in 'result'
        (in other words, this module can be used to fetch a record's current id, type, and ttl)
    type: str

  record_ttl:
    description:
      - record's "Time to live".  Number of seconds the record remains cached in DNS servers.
    default: 30
    type: int

  state:
    description:
      - whether the record should exist or not
    required: true
    choices: [ 'present' ]
    type: str

requirements: [ hashlib, hmac ]
author: "Brice Burgess (@briceburg) (Adapted to Constellix from DNSMadeEasy by Nolan Crooks (@crockk))"
'''

EXAMPLES = '''
- name: Fetch my.com domain records
  constellix:
    account_key: key
    account_secret: secret
    domain: my.com
    state: present
  register: response

- name: Update an A record
  constellix:
    account_key: key
    account_secret: secret
    domain: my.com
    state: present
    record_name: test
    record_value: 192.0.2.23

- name: Fetch a specific record
  constellix:
    account_key: key
    account_secret: secret
    domain: my.com
    state: present
    record_name: test
  register: response
'''

# ============================================
# Constellix module specific support methods.
#

import json
import hashlib
import hmac
import locale
import time
from base64 import b64encode
from time import strftime, gmtime

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url
from ansible.module_utils.six.moves.urllib.parse import urlencode
from ansible.module_utils.six import string_types


class ConstellixModule(object):

    def __init__(self, apikey, secret, domain, module):
        self.module = module

        self.api = apikey
        self.secret = secret

        self.baseurl = 'https://api.dns.constellix.com/v1/'

        self.domain = str(domain)
        self.domain_map = None      # ["domain_name"] => ID
        self.record_map = None      # ["record_name"] => ID
        self.records = None         # ["record_ID"] => <record>
        self.all_records = None
        self.contactList_map = None  # ["contactList_name"] => ID

        # Lookup the domain ID if passed as a domain name vs. ID
        if not self.domain.isdigit():
            self.domain = self.getDomainByName(self.domain)

        self.record_url = 'domains/' + str(self.domain['id']) + '/records'
        self.monitor_url = 'monitor'
        self.contactList_url = 'contactList'

    def _headers(self):
        now = self._current_time()
        hmac_hash = self._hmac_hash(now)
        headers = {
            'x-cnsdns-apiKey': self.api,
            'x-cnsdns-hmac': b64encode(hmac_hash),
            'x-cnsdns-requestDate': now,
            'Content-Type': 'application/json'
        }
        return headers

    def _hmac_hash(self, now):
        return hmac.new(self.secret.encode('utf-8'), now.encode('utf-8'), digestmod=hashlib.sha1).digest()

    def _current_time(self):
        return str(int(time.time() * 1000))

    def _create_hash(self, rightnow):
        return hmac.new(self.secret.encode(), rightnow.encode(), hashlib.sha1).hexdigest()

    def query(self, resource, method, data=None):
        url = self.baseurl + resource
        if data and not isinstance(data, string_types):
            data = urlencode(data)

        response, info = fetch_url(self.module, url, data=data, method=method, headers=self._headers())
        if info['status'] not in (200, 201, 204):
            self.module.fail_json(msg="%s returned %s, with body: %s" % (url, info['status'], info['msg']))

        try:
            return json.load(response)
        except Exception:
            return {}

    def getDomain(self, domain_id):
        if not self.domain_map:
            self._instMap('domain')

        return self.domains.get(domain_id, False)

    def getDomainByName(self, domain_name):
        if not self.domain_map:
            self._instMap('domain')

        return self.getDomain(self.domain_map.get(domain_name, 0))

    def getDomains(self):
        response = self.query('domains/search?exact=' + self.domain, 'GET')
#        self.module.warn(warning='%s' % response)
        return response #['data']

    def getRecord(self, record_id):
        if not self.record_map:
            self._instMap('record')

        return self.records.get(record_id, False)

    # Try to find a single record matching this one.
    # How we do this depends on the type of record. For instance, there
    # can be several MX records for a single record_name while there can
    # only be a single CNAME for a particular record_name. Note also that
    # there can be several records with different types for a single name.
    def getMatchingRecord(self, record_name, record_type, record_value):
        # Get all the records if not already cached
        if not self.all_records:
            self.all_records = self.getRecords()

        if record_type in ["A"]:
            for result in self.all_records:
                if result['name'] == record_name:
                    return result
            return False
        elif not record_type:
            for result in self.all_records:
                if result['name'] == record_name:
                    return result
            return False
        else:
            raise Exception('record_type not yet supported, record type: %s' % record_type)

    def getRecords(self):
        return self.query(self.record_url, 'GET') #['data']

    def _instMap(self, type):
        # @TODO cache this call so it's executed only once per ansible execution
        map = {}
        results = {}

        # iterate over e.g. self.getDomains() || self.getRecords()
        for result in getattr(self, 'get' + type.title() + 's')():
            map[result['name']] = result['id']
            results[result['id']] = result

        # e.g. self.domain_map || self.record_map
        setattr(self, type + '_map', map)
        setattr(self, type + 's', results)  # e.g. self.domains || self.records

    def prepareRecord(self, data):
        return json.dumps(data, separators=(',', ':'))

    def updateRecord(self, record_id, data):
        # @TODO update the cache w/ resultant record + id when impleneted
        return self.query(self.record_url + '/A/' + str(record_id), 'PUT', data)

# ===========================================
# Module execution.
#


def main():

    module = AnsibleModule(
        argument_spec=dict(
            account_key=dict(required=True, no_log=True),
            account_secret=dict(required=True, no_log=True),
            domain=dict(required=True),
            state=dict(required=True, choices=['present', 'absent']),
            record_name=dict(required=False),
            record_type=dict(required=False, default='A', choices=[
                             'A', 'AAAA', 'CNAME', 'ANAME', 'HTTPRED', 'MX', 'NS', 'PTR', 'SRV', 'TXT']),
            record_value=dict(required=False),
            record_ttl=dict(required=False, default=30, type='int')
        ),
    )

    Constellix = ConstellixModule(module.params["account_key"], module.params[
               "account_secret"], module.params["domain"], module)
    state = module.params["state"]
    record_name = module.params["record_name"]
    record_type = module.params["record_type"]
    record_value = module.params["record_value"]

    # Follow Keyword Controlled Behavior
    if record_name is None:
        domain_records = Constellix.getRecords()
        if not domain_records:
            module.fail_json(
                msg="The requested domain name is not accessible with this api_key; try using its ID if known.")
        module.exit_json(changed=False, result=domain_records)

    # Fetch existing record + Build new one
    current_record = Constellix.getMatchingRecord(record_name, record_type, record_value)
    new_record = {'name': record_name}
    for i in ["record_value", "record_type", "record_ttl"]:
        if not module.params[i] is None:
            new_record[i[len("record_"):]] = module.params[i]

    # Compare new record against existing one
    record_changed = False
    if current_record:
        for i in new_record:
            # Remove leading and trailing quote character from values because TXT records
            # are surrounded by quotes.
            if str(current_record[i]).strip('"') != str(new_record[i]):
                record_changed = True
        new_record['id'] = str(current_record['id'])

    # Follow Keyword Controlled Behavior
    if state == 'present':
        # return the record if no value is specified
        if "value" not in new_record:
            if not current_record:
                module.fail_json(
                    msg="A record with name '%s' does not exist for domain '%s.'" % (record_name, module.params['domain']))
            module.exit_json(changed=False, result=dict(record=current_record))

        # create record and monitor as the record does not exist
        if not current_record:
            record = Constellix.createRecord(Constellix.prepareRecord(new_record))

        # update the record
        updated = False
        if new_record['value'] == current_record['value'][0] and new_record['ttl'] == current_record['ttl']:
            module.exit_json(changed=False, result=dict(new_record=new_record, current_record=current_record))
        del new_record['id']
        new_record['recordOption'] = 'roundRobin'
        new_record['roundRobin'] = [{'value': new_record['value']}]
        del new_record['value']
        del new_record['type']
        new_record['ttl'] = str(new_record['ttl'])
#        module.exit_json(changed=True, result=dict(current_record=current_record, new_record=new_record))
        if record_changed:
            Constellix.updateRecord(current_record['id'], Constellix.prepareRecord(new_record))
            updated = True
        if updated:
            module.exit_json(changed=True, result=dict(record=new_record))

        # return the record (no changes)
        module.exit_json(changed=False, result=dict(record=current_record))

    else:
        module.fail_json(
            msg="'%s' is an unknown value for the state argument" % state)


if __name__ == '__main__':
    main()
