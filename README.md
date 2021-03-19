# Ansible module: constellix
### Short description: Interface with Constellix DNS API.
### Description:
Retrieve domain information, records within a specified domain, and update existing A records' value and TTL using the Constellix REST API. 

#### Options:
```
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
    - Record name to get/create/delete/update.
      If record_name is not specified; all records for the domain will be returned in "result" regardless of the
      state argument.
  type: str
record_value:
  description:
    - >
      Record value. HTTPRED: <redirection URL>, MX: <priority> <target name>, NS: <name server>, PTR: <target name>,
      SRV: <priority> <weight> <port> <target name>, TXT: <text value>"
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
```

#### Ansible examples
```
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
```
