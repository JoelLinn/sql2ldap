# 📋 sql2ldap 🍇

An LDAP server that presents SQL rows as LDAP leafs under a single DN.

## Overview

Many systems (e.g. PBX systems) require read-only access to information through an LDAP interface which is often stored using a relational SQL database.
Imagine you want to find a customers phone number from a dictionary on your desk phone or allow your phone system to do reverse name lookups of callers.
There are multiple ways to tackle this problem:

* Sync entries with a cron job to a traditional LDAP server. This does not scale well.
* Triggers on the SQL database to update the LDAP entries individually.
* Dynamically translate LDAP queries to SQL queries (this tool).

The recently deprecated `back_sql` backend of _OpenLDAP_ also supports the last option.
It is much more versatile (it can store complete trees) but therefore generates strongly fragmented _SQL_ query patterns (i.e. one unique query for each attribute of every result) - even for simple one-table, one-objectClass ,mappings like the ones this tool supports.

## Examples

You can find an examples using docker-compose with a PostgreSQL server [here][examples].

[examples]: https://github.com/joellinn/sql2ldap/tree/master/examples

## (Un)supported features

This tool uses [sqlx][sqlx] for database access, which supports a number of SQL databases.
At this time however, only PostgreSQL is implemented here.
Others should be easy to add and I'm happy to accept your contribution!

[sqlx]: https://github.com/launchbadge/sqlx

Currently no TLS or Authentication is implemented. It can be achieved by using _OpenLDAP_ with `back_ldap`.

## License

This project is licensed under the [GNU Affero General Public License v3.0 (AGPL-3.0-only)][license].

[license]: https://github.com/joellinn/sql2ldap/tree/master/LICENSE
