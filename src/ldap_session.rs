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

use std::sync::Arc;

use futures::TryStreamExt;
use ldap3_proto::proto::{
    LdapFilter, LdapMsg, LdapPartialAttribute, LdapResultCode, LdapSearchResultEntry,
};
use ldap3_proto::simple::{SearchRequest, SimpleBindRequest, WhoamiRequest};
use ldap3_proto::LdapSearchScope;
use sqlx::Row;

use crate::config::*;

pub struct LdapSession {
    conf: Arc<Config>,
    db_pool: Arc<sqlx::postgres::PgPool>,
    dn: String,
}

impl LdapSession {
    pub fn new(conf: Arc<Config>, db_pool: Arc<sqlx::postgres::PgPool>) -> Self {
        Self {
            conf,
            db_pool,
            dn: String::default(),
        }
    }

    pub async fn do_bind(&mut self, sbr: &SimpleBindRequest) -> LdapMsg {
        if sbr.dn == "" && sbr.pw == "" {
            self.dn = "Anonymous".to_owned();

            sbr.gen_success()
        } else {
            sbr.gen_invalid_cred()
        }
    }

    pub async fn do_search(&mut self, lsr: &SearchRequest, size_limit: i32) -> Vec<LdapMsg> {
        let base_lower = lsr.base.to_ascii_lowercase();
        let suffix_lower = self.conf.ldap.suffix.to_lowercase();
        let mut cn_base_search: Option<String> = None;

        // Tree discovery
        if lsr.scope == LdapSearchScope::Base {
            if lsr.base.is_empty() {
                return vec![
                    lsr.gen_result_entry(LdapSearchResultEntry {
                        dn: "".to_owned(),
                        attributes: vec![
                            LdapPartialAttribute {
                                atype: "objectClass".to_owned(),
                                vals: vec!["top".to_owned()],
                            },
                            LdapPartialAttribute {
                                atype: "namingContexts".to_owned(),
                                vals: vec![self.conf.ldap.suffix.to_owned()],
                            },
                        ],
                    }),
                    lsr.gen_success(),
                ];
            } else if suffix_lower.ends_with(&format!(",{}", base_lower)) {
                return vec![lsr.gen_success()];
            } else if base_lower == suffix_lower {
                let leaf_short = suffix_lower[0..suffix_lower.find("=").unwrap()].to_owned();
                let leaf_name = suffix_lower
                    [(suffix_lower.find("=").unwrap() + 1)..suffix_lower.find(",").unwrap()]
                    .to_owned();
                let object_class = match &leaf_short as &str {
                    "dc" => "dcObject".to_owned(),
                    "ou" => "organizationalUnit".to_owned(),
                    _ => {
                        log::error!("The base dn type \"{}\" is not implemented", leaf_short);
                        return vec![
                            lsr.gen_error(LdapResultCode::Other, "Not implemented".to_owned())
                        ];
                    }
                };
                return vec![
                    lsr.gen_result_entry(LdapSearchResultEntry {
                        dn: self.conf.ldap.suffix.to_owned(),
                        attributes: vec![
                            LdapPartialAttribute {
                                atype: "objectClass".to_owned(),
                                vals: vec![object_class],
                            },
                            LdapPartialAttribute {
                                atype: leaf_short,
                                vals: vec![leaf_name],
                            },
                            LdapPartialAttribute {
                                atype: "hasSubordinates".to_owned(),
                                vals: vec!["TRUE".to_owned()],
                            },
                            LdapPartialAttribute {
                                atype: "entryDN".to_owned(),
                                vals: vec![self.conf.ldap.suffix.to_owned()],
                            },
                        ],
                    }),
                    lsr.gen_success(),
                ];
            } else if base_lower.ends_with(&format!(",{}", &suffix_lower)) {
                let ident = &base_lower[0..base_lower.len() - suffix_lower.len() - 1];
                // TODO this can be improved
                let ident_split: Vec<&str> = ident.split("=").take(3).collect();
                if ident.contains(",") || ident_split.len() != 2 || ident_split[0] != "cn" {
                    return vec![lsr.gen_error(LdapResultCode::NoSuchObject, "".to_owned())];
                }
                cn_base_search = Some(ident_split[1].to_owned());
            } else {
                return vec![lsr.gen_error(LdapResultCode::NoSuchObject, String::new())];
            }
        } else if base_lower != suffix_lower {
            // no infinite tree depths
            return vec![lsr.gen_success()];
        }

        //
        // Build SQL query:
        //

        let mut query = match build_select(&self.conf.mappings, &lsr) {
            Ok(q) => q,
            Err(e) => {
                return e;
            }
        };

        query.push_str("FROM ");
        query.push_str(&self.conf.sql.table);
        query.push_str(" ");

        let (q_filter, bindings) = match cn_base_search {
            Some(cn) => {
                // Base scope, return just one object
                let mut q = "WHERE ".to_owned();
                let (_, _, col) = self.conf.mappings.get("cn").unwrap();
                q.push_str(col);
                q.push_str(" = $1 ");
                (q, vec![cn])
            }
            None => {
                // Search the complete dn
                match build_filter(&self.conf.mappings, &lsr) {
                    Ok(x) => x,
                    Err(e) => {
                        return e;
                    }
                }
            }
        };
        query.push_str(&q_filter);

        if size_limit > 0 {
            query.push_str(&format!("LIMIT {}", size_limit));
        }

        if log::log_enabled!(log::Level::Debug) {
            log::debug!("Query: {}", query);
            if !bindings.is_empty() {
                log::debug!("Params: \"{}\"", bindings.join("\", \""));
            }
        }

        let mut rows = {
            let mut q = sqlx::query(&query);
            for b in bindings {
                q = q.bind(b);
            }
            q.fetch(self.db_pool.as_ref())
        };
        let mut results: Vec<LdapMsg> = Vec::new();

        while let Some(row) = rows.try_next().await.unwrap() {
            let all = lsr.attrs.len() == 0 || lsr.attrs.contains(&"*".to_owned());
            let mut attributes = Vec::with_capacity(if all {
                self.conf.mappings.len()
            } else {
                lsr.attrs.len()
            });

            let mut add_attribute = |attr: String, col: &str| {
                let value: Option<String> = row.try_get(col).unwrap();

                if let Some(x) = value.filter(|s| s.len() > 0) {
                    attributes.push(LdapPartialAttribute {
                        atype: attr,
                        vals: vec![x],
                    })
                };
            };
            if all {
                // Return all attributes
                for (attr_lowercase, attr, _) in &self.conf.mappings {
                    add_attribute(attr.to_string(), &attr_lowercase);
                }
            } else {
                // Only requested attributes
                for attr_search in &lsr.attrs {
                    // Add with proper case
                    if let Some((attr_lower, attr, _)) = self.conf.mappings.get(&attr_search) {
                        add_attribute(attr.to_string(), attr_lower);
                    }
                }
            }

            let mut dn = "cn=".to_owned() + row.try_get::<&str, _>("cn").unwrap();
            if self.conf.ldap.suffix.len() > 0 {
                dn.push_str(",");
                dn.push_str(&self.conf.ldap.suffix);
            }
            results.push(lsr.gen_result_entry(LdapSearchResultEntry { dn, attributes }));
        }

        results.push(lsr.gen_success());
        results
    }

    pub fn do_whoami(&mut self, wr: &WhoamiRequest) -> LdapMsg {
        wr.gen_success(format!("dn: {}", self.dn).as_str())
    }
}

fn build_select(mappings: &Mappings, lsr: &SearchRequest) -> Result<String, Vec<LdapMsg>> {
    let mut q = "SELECT ".to_owned();

    let mut cols = Vec::new();
    if lsr.attrs.len() > 0 && !lsr.attrs.contains(&"*".to_owned()) {
        // Just hit the db with the requested attributes
        let mut has_cn = false;
        for attr_search in &lsr.attrs {
            if let Some((attr_lower, _, col)) = mappings.get(&attr_search) {
                if attr_lower == "cn" {
                    has_cn = true;
                }
                cols.push(format!("{} AS {}", col, attr_lower));
            }
        }

        if !has_cn {
            // cn is always required to build the dn
            let (_, _, cn_col) = mappings.get("cn").unwrap();
            cols.push(format!("{} AS cn", cn_col));
        }
    } else {
        for (attr_lowercase, _, col) in mappings {
            cols.push(format!("{} AS {}", col, attr_lowercase))
        }
    }

    q.push_str(&cols.join(", "));
    q.push_str(" ");

    Ok(q)
}

fn build_filter(
    mappings: &Mappings,
    lsr: &SearchRequest,
) -> Result<(String, Vec<String>), Vec<LdapMsg>> {
    let mut query = "WHERE ".to_owned();
    let mut bindings = Vec::new();
    // Translate filter recursively:
    build_filter_inner(mappings, lsr, &lsr.filter, &mut query, &mut bindings)?;
    Ok((query, bindings))
}

fn build_filter_inner(
    mappings: &Mappings,
    lsr: &SearchRequest,
    ldap_filter: &LdapFilter,
    query: &mut String,
    bindings: &mut Vec<String>,
) -> Result<(), Vec<LdapMsg>> {
    let sanitize = |s: &str| {
        // TODO proper escape
        s.replace("%", "\\%").replace("_", "\\_")
    };
    let get_token = || format!("${}", bindings.len() + 1);
    let get_mapping = |attr: &str| -> Result<&str, Vec<LdapMsg>> {
        match mappings.get(attr) {
            Some((_, _, col)) => Ok(col),
            None => Ok("''"), //Err(vec![lsr.gen_operror(&format!("Unknown filter attribute: {}", attr))]),
        }
    };
    let mut join_filter_group = |filters: &Vec<LdapFilter>,
                                 sep: &str,
                                 bindings: &mut Vec<String>|
     -> Result<(), Vec<LdapMsg>> {
        if filters.len() > 0 {
            query.push_str("(");
            let mut i = filters.iter();
            let mut f = i.next();
            loop {
                build_filter_inner(mappings, lsr, f.unwrap(), query, bindings)?;
                f = i.next();
                if f.is_none() {
                    break;
                }
                query.push_str(sep);
            }
            query.push_str(") ");
        }
        Ok(())
    };

    match ldap_filter {
        LdapFilter::And(filters) => join_filter_group(filters, "AND ", bindings),
        LdapFilter::Or(filters) => join_filter_group(filters, "OR ", bindings),
        LdapFilter::Not(filter) => {
            query.push_str("(NOT ");
            build_filter_inner(mappings, lsr, filter, query, bindings)?;
            query.push_str(") ");
            Ok(())
        }
        LdapFilter::Equality(attr, value) => {
            let col = get_mapping(attr)?;
            query.push_str("LOWER(");
            query.push_str(col);
            query.push_str(") = LOWER(");
            query.push_str(&get_token());
            query.push_str(") ");
            bindings.push(sanitize(value));
            Ok(())
        }
        LdapFilter::Substring(attr, filter) => {
            let col = get_mapping(attr)?;
            let mut filter_str = filter
                .initial
                .as_ref()
                .map_or_else(|| String::default(), |s| sanitize(s) + "%");
            if filter_str.is_empty() && !filter.any.is_empty() {
                filter_str += "%";
            }
            for s in &filter.any {
                filter_str += &sanitize(s);
                filter_str += "%";
            }
            filter_str += &filter
                .final_
                .as_ref()
                .map_or_else(|| String::default(), |s| sanitize(s));

            query.push_str("LOWER(");
            query.push_str(col);
            query.push_str(") LIKE LOWER(");
            query.push_str(&get_token());
            query.push_str(") ");
            bindings.push(filter_str);
            Ok(())
        }
        LdapFilter::Present(attr) => {
            let col = get_mapping(attr)?;
            query.push_str(col);
            query.push_str(" <> '' ");
            Ok(())
        }
        #[allow(unreachable_patterns)]
        _ => Err(vec![lsr.gen_error(
            LdapResultCode::Other,
            "Filter not implemented".to_owned(),
        )]),
    }
}
