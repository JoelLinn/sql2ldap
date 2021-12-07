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

use std::cell::RefCell;
use std::convert::TryFrom;
use std::fs::File;
use std::io::Read;
use std::net;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

mod config;
mod ldap_session;
use self::config::Config;
use self::ldap_session::LdapSession;

use clap::{App, Arg, ArgMatches};
use futures::{SinkExt, StreamExt};
use ldap3_server::simple::*;
use ldap3_server::LdapCodec;
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{FramedRead, FramedWrite};

static DEFAULT_CONFIG_FILE: &str = "/etc/sql2ldap.toml";
static DEFAULT_USER: &str = "nobody";
static DEFAULT_GROUP: &str = "nogroup";

static SECCOMP_ARMED: AtomicBool = AtomicBool::new(false);
thread_local!(static SECCOMP_INSTALLED: RefCell<bool> = RefCell::new(false));

fn main() -> Result<(), String> {
    let cmd = load_command_line();

    if cmd.is_present("license") {
        print_license();
        return Ok(());
    }

    let config: Arc<Config> = Arc::new({
        let mut c: Config = load_config(cmd.value_of("config").unwrap())?;
        if cmd.is_present("debug") {
            c.server.debug = true;
        }
        c
    });

    {
        use simplelog::{
            ColorChoice, CombinedLogger, Config, LevelFilter, TermLogger, TerminalMode,
        };
        let level = if config.server.debug {
            LevelFilter::Debug
        } else {
            LevelFilter::Warn
        };
        CombinedLogger::init(vec![
            TermLogger::new(
                level,
                Config::default(),
                TerminalMode::Mixed,
                ColorChoice::Auto,
            ),
            // TODO add file logger
        ])
        .map_err(|err| format!("Could not initialize logger: {}", err))?;
    }

    // Bind before dropping privileges:
    let addr = net::SocketAddr::new(config.server.ip, config.server.port);
    let listener = std::net::TcpListener::bind(&addr)
        .map_err(|err| format!("Can not bind to {}: {}", addr, err))?;
    listener.set_nonblocking(true).unwrap();

    drop_privileges()?;

    let seccomp_programs = if config.server.seccomp
        && cfg!(target_os = "linux")
        && (cfg!(target_arch = "x86_64") || cfg!(target_arch = "aarch64"))
    {
        log::warn!("🧪 The seccomp filtering is highly experimental and known to crash in some configurations! 🧪");
        Some(
            build_seccomp_program()
                .map_err(|err| format!("Error compiling seccomp filter: {}", err))?,
        )
    } else {
        None
    };

    let mut rt_builder = tokio::runtime::Builder::new_multi_thread();
    if config.server.seccomp {
        rt_builder.max_blocking_threads(1);
    }
    if cfg!(target_os = "linux") && config.server.seccomp {
        rt_builder.on_thread_unpark(move || {
            if !SECCOMP_INSTALLED.with(|f| *f.borrow()) && SECCOMP_ARMED.load(Ordering::Acquire) {
                log::debug!("installing seccomp filter for tid {}", unsafe {
                    libc::syscall(libc::SYS_gettid)
                });
                for p in seccomp_programs.as_ref().unwrap() {
                    seccompiler::apply_filter(p).expect("Error applying seccomp filter");
                }
                SECCOMP_INSTALLED.with(|f| *f.borrow_mut() = true);
            }
        });
    }
    rt_builder
        .worker_threads(config.server.threads)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let (con_opts, pool_opts) = build_pg_connect_options(&config);
            let db_pool = Arc::new(
                pool_opts
                    .connect_with(con_opts)
                    .await
                    .map_err(|err| format!("Could not connect to database: {}", err))?,
            );

            // Apply seccomp filters after db connections where opened
            SECCOMP_ARMED.store(true, Ordering::Release);

            let listener_tokio = Box::new(TcpListener::from_std(listener).unwrap());

            // Initiate the acceptor task.
            tokio::spawn(acceptor(listener_tokio, config, db_pool));

            log::info!("serving ldap://{} ...", addr);
            if cfg![target_family = "unix"] {
                use tokio::signal::unix::*;
                let err_msg = |err| format!("Failed to install signal handler: {}", err);

                let mut int = signal(SignalKind::interrupt()).map_err(err_msg)?;
                let mut term = signal(SignalKind::terminate()).map_err(err_msg)?;
                tokio::select! {
                    _ = int.recv() => {},
                    _ = term.recv() => {},
                }
            } else {
                tokio::signal::ctrl_c().await.unwrap();
            }
            Ok(())
        })
}

fn load_command_line() -> ArgMatches<'static> {
    let matches = App::new(clap::crate_name!())
        .version(clap::crate_version!())
        .author(clap::crate_authors!())
        .about("Present relational SQL data 📋 to LDAP clients 🍇")
        .arg(
            Arg::with_name("config")
                .long("config")
                .short("c")
                .value_name("FILE")
                .default_value(DEFAULT_CONFIG_FILE)
                .help("Sets the configuration file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("debug")
                .long("debug")
                .help("Prints the generated SQL queries"),
        )
        .arg(
            Arg::with_name("license")
                .long("license")
                .help("Prints the program license and exits"),
        )
        .get_matches();
    matches
}

fn print_license() {
    let license_header = format!(
        r#"Copyright (C) 2021  {}
This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, version 3.
This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.
You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>"#,
        clap::crate_authors!()
    );
    let license = include_str!("../LICENSE");
    println!("{}", &license_header);
    println!();
    println!();
    println!();
    print!("{}", license);
}

fn load_config(config_toml_filename: &str) -> Result<Config, String> {
    let config_toml = match File::open(config_toml_filename) {
        Ok(mut f) => {
            let mut toml = String::new();
            if let Err(err) = f.read_to_string(&mut toml) {
                return Err(format!(
                    "Error reading config file {}: {}",
                    config_toml_filename, err
                ));
            }
            toml
        }
        Err(err) => {
            return Err(format!(
                "Error opening config file {}: {}",
                config_toml_filename, err
            ));
        }
    };
    toml::from_str::<Config>(&config_toml).map_err(|err| {
        format!(
            "Error parsing config file {}: {}",
            config_toml_filename, err
        )
    })
}

fn build_pg_connect_options(
    conf: &Config,
) -> (
    sqlx::postgres::PgConnectOptions,
    sqlx::postgres::PgPoolOptions,
) {
    let mut con_opts = sqlx::postgres::PgConnectOptions::new()
        .username(&conf.sql.user)
        .password(&conf.sql.pass)
        .database(&conf.sql.database)
        .application_name(clap::crate_name!());
    con_opts = match conf.sql.socket() {
        Some(socket) => con_opts.socket(socket),
        None => con_opts.host(&conf.sql.host),
    };
    if let Some(port) = conf.sql.port {
        con_opts = con_opts.port(port);
    }

    let t = conf.server.threads as u32;
    let mut pool_opts = sqlx::postgres::PgPoolOptions::new();
    if conf.server.seccomp {
        // Can't open a connection when seccomp filter is active
        pool_opts = pool_opts
            .max_lifetime(None)
            .idle_timeout(None)
            .max_connections(t)
            .min_connections(t);
    }

    (con_opts, pool_opts)
}

fn drop_privileges() -> Result<bool, String> {
    if cfg!(target_family = "unix") {
        if unsafe { libc::geteuid() == 0 } {
            let (uid, gid) = load_uid_gid()?;
            if unsafe { libc::setgid(gid) != 0 } {
                Err(format!("setgid({}) failed", gid))?
            }
            let default_group = std::ffi::CString::new(DEFAULT_GROUP).unwrap();
            if unsafe { libc::initgroups(default_group.as_ptr(), gid) != 0 } {
                Err(format!("initgroups(\"{}\", {}) failed", DEFAULT_GROUP, gid))?
            }

            let ul_0 = 0 as libc::c_ulong;
            let ul_1 = 1 as libc::c_ulong;
            if unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, ul_0, ul_0, ul_0, ul_0) } != 0 {
                Err("prctl(PR_SET_KEEPCAPS, 0) failed".to_owned())?
            }
            if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, ul_1, ul_0, ul_0, ul_0) } != 0 {
                Err("prctl(PR_SET_NO_NEW_PRIVS, 1) failed".to_owned())?
            }

            // This will set throw invalid arguments at older kernels:
            // caps::clear(None, caps::CapSet::Bounding)
            //     .map_err(|err| format!("Could not clear bounding capabilities: {}", err))?;
            if unsafe { libc::setuid(uid) == -1 } {
                Err(format!("setuid({}) failed", uid))?
            }
            caps::clear(None, caps::CapSet::Inheritable)
                .map_err(|err| format!("Could not clear inheritable capabilities: {}", err))?;

            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(target_family = "unix")]
fn load_uid_gid() -> Result<(libc::uid_t, libc::gid_t), String> {
    let default_user = std::ffi::CString::new(DEFAULT_USER).unwrap();
    let default_group = std::ffi::CString::new(DEFAULT_GROUP).unwrap();
    let uid = unsafe {
        let pwd = libc::getpwnam(default_user.as_ptr());
        if pwd.is_null() {
            Err(format!("getpwnam(\"{}\") failed", DEFAULT_USER))
        } else {
            Ok((*pwd).pw_uid)
        }
    }?;
    let gid = unsafe {
        let grp = libc::getgrnam(default_group.as_ptr());
        if grp.is_null() {
            Err(format!("getgrnam(\"{}\") failed", DEFAULT_GROUP))
        } else {
            Ok((*grp).gr_gid)
        }
    }?;
    Ok((uid, gid))
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn build_seccomp_program() -> Result<Vec<BpfProgram>, seccompiler::BackendError> {
    let len_pointer = if cfg!(target_pointer_width = "32") {
        || SeccompCmpArgLen::Dword
    } else {
        || SeccompCmpArgLen::Qword
    };
    let len_long = len_pointer;
    let target_arch = if cfg!(target_arch = "x86_64") {
        TargetArch::x86_64
    } else if cfg!(target_arch = "aarch64") {
        TargetArch::aarch64
    } else {
        panic!();
    };
    let filter_allow = SeccompFilter::new(
        vec![
            // TODO socket and connect are only needed because sqlx pool will not pre-connect them
            // https://github.com/launchbadge/sqlx/pull/1527
            // (libc::SYS_socket, vec![]),
            // (libc::SYS_connect, vec![]),
            (libc::SYS_sendto, vec![]),
            (libc::SYS_shutdown, vec![]),
            (libc::SYS_getsockopt, vec![]),
            (libc::SYS_epoll_wait, vec![]),
            (libc::SYS_epoll_pwait, vec![]),
            (libc::SYS_epoll_ctl, vec![]),
            (libc::SYS_accept, vec![]),
            (libc::SYS_accept4, vec![]),
            (libc::SYS_recvfrom, vec![]),
            // general purpose
            (libc::SYS_read, vec![]),
            (libc::SYS_write, vec![]),
            (libc::SYS_writev, vec![]),
            (libc::SYS_close, vec![]),
            (libc::SYS_lseek, vec![]),
            (libc::SYS_exit, vec![]),
            (libc::SYS_futex, vec![]),
            (libc::SYS_getuid, vec![]),
            (libc::SYS_geteuid, vec![]),
            (libc::SYS_getgid, vec![]),
            (libc::SYS_getegid, vec![]),
            (libc::SYS_getrandom, vec![]),
            (libc::SYS_clock_gettime, vec![]),
            (libc::SYS_clock_getres, vec![]),
            (
                libc::SYS_ioctl,
                vec![SeccompRule::new(vec![
                    // isatty()
                    SeccompCondition::new(0, len_long(), SeccompCmpOp::Eq, 1 as u64)?, // fd == stdout
                    SeccompCondition::new(1, len_long(), SeccompCmpOp::Eq, libc::TCGETS as u64)?,
                ])?],
            ),
            // signal handling:
            (
                libc::SYS_rt_sigaction,
                vec![
                    // CTRL + C
                    SeccompRule::new(vec![SeccompCondition::new(
                        0,
                        SeccompCmpArgLen::Dword,
                        SeccompCmpOp::Eq,
                        libc::SIGINT as u64,
                    )?])?,
                ],
            ),
            (libc::SYS_rt_sigprocmask, vec![]),
            (libc::SYS_rt_sigreturn, vec![]),
            // (libc::SYS_tgkill, vec![]),
            (libc::SYS_sigaltstack, vec![]),
            // memory management
            (
                libc::SYS_mmap,
                vec![SeccompRule::new(vec![
                    SeccompCondition::new(
                        2,
                        SeccompCmpArgLen::Dword,
                        SeccompCmpOp::MaskedEq(libc::PROT_EXEC as u64),
                        0u64,
                    )?, // (protection & PROT_EXEC) = 0
                    SeccompCondition::new(4, SeccompCmpArgLen::Dword, SeccompCmpOp::Ge, 0u64)?, // fd > 0
                ])?],
            ),
            (
                libc::SYS_mprotect,
                vec![SeccompRule::new(vec![
                    SeccompCondition::new(
                        2,
                        SeccompCmpArgLen::Dword,
                        SeccompCmpOp::MaskedEq(libc::PROT_EXEC as u64),
                        0u64,
                    )?, // (protection & PROT_EXEC) = 0
                ])?],
            ),
            (libc::SYS_mremap, vec![]),
            (libc::SYS_munmap, vec![]),
            (libc::SYS_madvise, vec![]),
            (libc::SYS_brk, vec![]),
        ]
        .into_iter()
        .collect(),
        SeccompAction::Trap,
        SeccompAction::Allow,
        target_arch,
    )?;
    Ok(vec![filter_allow.try_into()?])
}

async fn acceptor(
    listener: Box<TcpListener>,
    config: Arc<Config>,
    db_pool: Arc<sqlx::postgres::PgPool>,
) {
    loop {
        match listener.accept().await {
            Ok((socket, paddr)) => {
                tokio::spawn(handle_client(
                    socket,
                    paddr,
                    config.clone(),
                    db_pool.clone(),
                ));
            }
            Err(_e) => {
                //pass
            }
        }
    }
}

async fn handle_client(
    socket: TcpStream,
    _paddr: net::SocketAddr,
    config: Arc<Config>,
    db_pool: Arc<sqlx::postgres::PgPool>,
) {
    // Configure the codec etc.
    let (r, w) = tokio::io::split(socket);
    let mut reqs = FramedRead::new(r, LdapCodec);
    let mut resp = FramedWrite::new(w, LdapCodec);
    let mut session = LdapSession::new(config, db_pool);

    while let Some(msg) = reqs.next().await {
        // TODO switch to full Op handling
        let search_sizelimit = match &msg {
            Ok(msg) => match &msg.op {
                ldap3_server::proto::LdapOp::SearchRequest(req) => req.sizelimit,
                _ => 0,
            },
            Err(_) => 0,
        };

        let server_op = match msg
            .map_err(|_e| ())
            .and_then(|msg| ServerOps::try_from(msg))
        {
            Ok(v) => v,
            Err(_) => {
                let _err = resp
                    .send(DisconnectionNotice::gen(
                        LdapResultCode::Other,
                        "Internal Server Error",
                    ))
                    .await;
                let _err = resp.flush().await;
                return;
            }
        };

        let result = match server_op {
            ServerOps::SimpleBind(sbr) => vec![session.do_bind(&sbr).await],
            ServerOps::Search(sr) => session.do_search(&sr, search_sizelimit).await,
            ServerOps::Unbind(_) => {
                return;
            }
            ServerOps::Whoami(wr) => vec![session.do_whoami(&wr)],
        };

        for rmsg in result.into_iter() {
            if let Err(_) = resp.send(rmsg).await {
                return;
            }
        }

        if let Err(_) = resp.flush().await {
            return;
        }
    }
    // Client disconnected
}
