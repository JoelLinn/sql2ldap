#!/bin/sh

# sleep to wait for slapd startup is unstable but ok for a POC
sleep 5 && \
ldapadd -H ldapi:// -f /ldap_conf/01_olcLdapMod.ldif && \
ldapadd -H ldapi:// -f /ldap_conf/02_olcLdapDb.ldif && \
ldapadd -H ldapi:// -f /ldap_conf/03_olcFrontendSizeLim.ldif && \
ldapadd -H ldapi:// -D "cn=admin,dc=example,dc=com" -w adminpassword -f ldap_conf/04_data.ldif &
