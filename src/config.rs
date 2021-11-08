// Copyright (C) 2021  Joel Linn
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use std::collections::HashMap;
use std::fmt;
use std::iter::FusedIterator;
use std::marker::PhantomData;

use serde::de::{Deserialize, MapAccess, Visitor};
use serde::Deserializer;
use serde_derive::Deserialize;

#[derive(Deserialize)]
pub struct Config {
    pub server: ConfigServer,
    pub sql: ConfigSql,
    pub ldap: ConfigLdap,
    pub mappings: Mappings,
}

#[derive(Deserialize)]
pub struct ConfigServer {
    #[serde(default = "default_server_ip")]
    pub ip: std::net::IpAddr,
    #[serde(default = "default_server_port")]
    pub port: u16,
    #[serde(default = "default_server_threads")]
    pub threads: usize,
    #[serde(default = "default_server_seccomp")]
    pub seccomp: bool,
    #[serde(default = "default_server_debug")]
    pub debug: bool,
}

fn default_server_ip() -> std::net::IpAddr {
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))
}
fn default_server_port() -> u16 {
    389
}
fn default_server_threads() -> usize {
    // This uses the same method as tokio:
    num_cpus::get()
}
fn default_server_seccomp() -> bool {
    false
}
fn default_server_debug() -> bool {
    false
}

#[derive(Deserialize)]
pub struct ConfigSql {
    pub backend: ConfigSqlBackend,
    pub host: String,
    pub port: Option<u16>,
    pub user: String,
    pub pass: String,
    pub database: String,
    pub table: String,
}

impl ConfigSql {
    pub fn socket(&self) -> Option<&str> {
        if self.host.starts_with("unix://") {
            Some(&self.host["unix://".len()..])
        } else {
            None
        }
    }
}

#[derive(Deserialize)]
pub enum ConfigSqlBackend {
    PostgreSQL,
}

#[derive(Deserialize)]
pub struct ConfigLdap {
    pub suffix: String,
}

pub struct Mappings {
    mappings: HashMap<String, (String, String)>,
}

impl Mappings {
    pub fn new() -> Mappings {
        Mappings {
            mappings: HashMap::new(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Mappings {
        Mappings {
            mappings: HashMap::with_capacity(capacity),
        }
    }

    pub fn insert(&mut self, attr: String, col: String) {
        self.mappings.insert(attr.to_ascii_lowercase(), (attr, col));
    }

    pub fn get(&self, attr: &str) -> Option<(&str, &str, &str)> {
        self.mappings
            .get_key_value(&attr.to_ascii_lowercase())
            .map(|(attr_lower, (attr, col))| (attr_lower as &str, attr as &str, col as &str))
    }

    pub fn len(&self) -> usize {
        self.mappings.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str, &str)> {
        self.into_iter()
    }
}

impl<'a> IntoIterator for &'a Mappings {
    type Item = (&'a str, &'a str, &'a str);
    type IntoIter = MappingsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        MappingsIter {
            iter: self.mappings.iter(),
        }
    }
}

pub struct MappingsIter<'a> {
    iter: std::collections::hash_map::Iter<'a, String, (String, String)>,
}

impl<'a> Iterator for MappingsIter<'a> {
    type Item = (&'a str, &'a str, &'a str);
    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        self.iter
            .next()
            .map(|(attr_lower, (attr, col))| (attr_lower as &str, attr as &str, col as &str))
    }
}

impl ExactSizeIterator for MappingsIter<'_> {
    fn len(&self) -> usize {
        self.iter.len()
    }
}

impl FusedIterator for MappingsIter<'_> {}

//
// Deserialization implementation
// https://serde.rs/deserialize-map.html
//
struct MappingsVisitor {
    marker: PhantomData<for<'a> fn() -> Mappings>,
}

impl MappingsVisitor {
    fn new() -> Self {
        MappingsVisitor {
            marker: PhantomData,
        }
    }
}

impl<'de> Visitor<'de> for MappingsVisitor {
    type Value = Mappings;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a map with ldap attributes as keys and sql column names as values")
    }

    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut map = Mappings::with_capacity(access.size_hint().unwrap_or(0));

        while let Some((key, value)) = access.next_entry()? {
            map.insert(key, value);
        }

        Ok(map)
    }
}

impl<'de> Deserialize<'de> for Mappings {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(MappingsVisitor::new())
    }
}
