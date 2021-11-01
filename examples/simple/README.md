# Simple example

This is a simple example on how to use _sql2ldap_.
Simply run the following command to start the servers:

```sh
sudo docker-compose up -d
```

_sql2ldap_ is then listening at port `389` and the mapped _PostgreSQL_ database can be queried using standard ldap tools:


```sh
# baseDN:       ou=customers,dc=example,dc=com
# filter:       (&(o=Company Co.)(sn=Kar*))
# attributes:   displayName mobile
ldapsearch -x -b "ou=customers,dc=example,dc=com" -H ldap://localhost:389 "(&(o=Company Co.)(sn=Kar*))" displayName mobile
```

To which _sql2ldap_ will answer:

```ldiff
# extended LDIF
#
# LDAPv3
# base <ou=customers,dc=example,dc=com> with scope subtree
# filter: (&(o=Company Co.)(sn=Kar*))
# requesting: displayName mobile
#

# 719, customers, example.com
dn: cn=719,ou=customers,dc=example,dc=com
displayName: Company Co.: Karunanithi, Guenter
mobile: +331111829

# 1255, customers, example.com
dn: cn=1255,ou=customers,dc=example,dc=com
displayName: Company Co.: Karunanithi, Ortrud
mobile: +331112365

# search result
search: 2
result: 0 Success

# numResponses: 3
# numEntries: 2
```
