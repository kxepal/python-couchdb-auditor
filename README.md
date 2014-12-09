python-couchdb-auditor
======================

This python port of [audit_couchdb](https://github.com/iriscouch/audit_couchdb) 
tool to audit Apache CouchDB server configuration and security issues.


What does it? 
-------------

 * Check actual CVE issues for your CouchDB version (however, it should be 
   quite old one);
 * Remind you to fix Admin Party if it is on your server;
 * Detect following plugins:
   - [GeoCouch](https://github.com/couchbase/geocouch)
   - [Facebook Authentication](https://github.com/ocastalabs/CouchDB-Facebook-Authentication)
   - [BrowserID](https://github.com/iriscouch/browserid_couchdb)
 * Check authentication handlers, detect missed and strange ones;
 * Inspect server administrators;
 * Check what query servers are available and what are missed;
 * Audit CouchDB users: check database admins and members, detect outdated ones;
 * Warn you, if database is not protected by security preferences or 
   `validate_doc_update` function;
 * Make short report about design documents.


How to use it?
--------------

Just clone repo and run install:

```
~ $ git clone https://github.com/kxepal/python-couchdb-auditor 
~ $ cd couchdb-auditor
couchdb-auditor $ python setup.py install
```

Python 2.6+ and [couchdb-python](https://github.com/djc/couchdb-python) are
required. 

To run audit your server as anonymous user just type:

```
~ $ couchdb-auditor http://localhost:5984/
```


Example output
--------------

```
~ $ couchdb-auditor http://localhost:5984
 * Server: http://localhost:5984
[II]  [audit_server]            http://localhost:5984
[II]  [check_version]           CouchDB version: 1.1.1
[II]  [check_CVE_issues]        Not affected by all known issues
[WW]  [check_audit_user]        Auditing as: admin party ; site-wide roles: _admin
[EE]  [check_config_access]     Configuration is open for anyone
[EE]  [check_admins]            This couch is in Admin Party. Log in to Futon (/_utils) and click "Fix this": http://localhost:5984/_utils
[II]  [check_auth_handlers]     Authentication handlers are well known: oauth, cookie, default
[II]  [check_geocouch]          Looks like GeoCouch is plugged in
[II]  [check_browserid]         Looks like BrowserID is plugged in
[II]  [check_facebook_auth]     Looks like Facebook Authentication is plugged in
[WW]  [check_db_users]          Found about 0 registered users

 * Database: http://localhost:5984/_replicator
[II]  [audit_database]          _replicator
[EE]  [check_db_security]       Database shares Admin Party state! Anyone could drop it with all 1 documents
[II]  [check_db_security]       Database is protected by next design documents: _replicator

 * DDoc: http://localhost:5984/_replicator/_design/_replicator
[II]  [audit_ddoc]              _design/_replicator
[II]  [check_ddoc_language]     Design language used: javascript
[II]  [check_ddoc_validate_func]  validate_doc_update function exists

 * Database: http://localhost:5984/_users
[II]  [audit_database]          _users
[EE]  [check_db_security]       Database shares Admin Party state! Anyone could drop it with all 1 documents
[II]  [check_db_security]       Database is protected by next design documents: _auth

 * DDoc: http://localhost:5984/_users/_design/_auth
[II]  [audit_ddoc]              _design/_auth
[II]  [check_ddoc_language]     Design language used: javascript
[II]  [check_ddoc_validate_func]  validate_doc_update function exists

```
