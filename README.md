# 📋 sql2ldap 🍇

An LDAP server that presents SQL rows as LDAP leafs under a single DN

## Overview

Many systems (e.g. PBX systems) require read-only access to information through an LDAP interface which is often stored using a relational SQL database.
Imagine you want to find a customers phone number from a dictionary on your desk phone or allow your phone system to do reverse name lookups of callers.
There are multiple ways to tackle this problem:

* Sync entries with a cron job to a traditional LDAP server. This does not scale well.
* Triggers on the SQL database to update the LDAP entries individually.
* Dynamically translate LDAP queries to SQL queries (this tool).

## Example

You can find an example using docker-compose with a PostgreSQL server [here][example-simple].

[example-simple]: https://github.com/joellinn/sql2ldap/tree/master/examples/simple

## (Un)supported features

This tool uses [sqlx][sqlx] for database access, which supports a number of SQL databases.
At this time however, only PostgreSQL is implemented here.
Others should be easy to add and I'm happy to accept your contribution!

[sqlx]: https://github.com/launchbadge/sqlx

## License

This project is licensed under the [GNU Affero General Public License v3.0 (AGPL-3.0-only)][license].

[license]: https://github.com/joellinn/sql2ldap/tree/master/LICENSE
