// SPDX-License-Identifier: LGPL-2.1-or-later
use resolved::config::{parse_server, Config};
use resolved::daemon::{install_signal_handlers, request_stop, run_stub};
use resolved::resolver::Resolver;
use resolved::varlink::VarlinkServer;
use std::env;
use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::thread;

#[derive(Debug)]
struct Options {
    config: PathBuf,
    listeners: Vec<String>,
    proxy_listeners: Vec<String>,
    upstreams: Vec<String>,
    varlink: Option<PathBuf>,
    runtime_directory: Option<PathBuf>,
    workers: Option<usize>,
    port: Option<u16>,
    check_config: bool,
    no_stub: bool,
    no_varlink: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            config: PathBuf::from("/etc/systemd/resolved.conf"),
            listeners: Vec::new(),
            proxy_listeners: Vec::new(),
            upstreams: Vec::new(),
            varlink: None,
            runtime_directory: None,
            workers: None,
            port: None,
            check_config: false,
            no_stub: false,
            no_varlink: false,
        }
    }
}

fn main() -> ExitCode {
    match execute() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("systemd-resolved: {error}");
            ExitCode::FAILURE
        }
    }
}

fn execute() -> Result<(), Box<dyn Error>> {
    let Some(options) = parse_options()? else {
        return Ok(());
    };

    let mut config = Config::load(&options.config)?;
    if !options.listeners.is_empty() {
        config.listeners = parse_servers(&options.listeners)?;
    }
    if !options.proxy_listeners.is_empty() {
        config.proxy_listeners = parse_servers(&options.proxy_listeners)?;
    }
    if !options.upstreams.is_empty() {
        config.upstreams = parse_servers(&options.upstreams)?;
        config.fallback_upstreams.clear();
    }
    if let Some(path) = options.varlink {
        config.varlink_path = path;
    }
    if let Some(path) = options.runtime_directory {
        config.runtime_directory = path;
    }
    if let Some(workers) = options.workers {
        config.workers = workers;
    }
    if let Some(port) = options.port {
        rewrite_ports(&mut config.listeners, port);
        rewrite_ports(&mut config.proxy_listeners, port);
    }
    if options.no_stub {
        config.listeners.clear();
        config.proxy_listeners.clear();
    }
    config.validate()?;

    if options.check_config {
        print_configuration(&config, options.no_varlink);
        return Ok(());
    }
    if options.no_varlink && config.listeners.is_empty() && config.proxy_listeners.is_empty() {
        return Err("all resolver interfaces are disabled".into());
    }

    install_signal_handlers()?;
    config.write_runtime_resolv_confs()?;

    let resolver = Arc::new(Resolver::new(config.clone()));
    if config.effective_upstreams().is_empty() {
        eprintln!("systemd-resolved: warning: no upstream DNS servers are configured");
    }

    let varlink_thread = if options.no_varlink {
        None
    } else {
        let server = VarlinkServer::new(config.varlink_path.clone(), Arc::clone(&resolver));
        Some(
            thread::Builder::new()
                .name("resolved-varlink".to_owned())
                .spawn(move || {
                    if let Err(error) = server.run() {
                        eprintln!("systemd-resolved: Varlink server failed: {error}");
                        request_stop();
                    }
                })?,
        )
    };

    for address in &config.listeners {
        eprintln!("systemd-resolved: full stub listening on {address} (UDP/TCP)");
    }
    for address in &config.proxy_listeners {
        eprintln!("systemd-resolved: proxy stub listening on {address} (UDP/TCP)");
    }

    let result = run_stub(resolver);
    request_stop();
    if let Some(thread) = varlink_thread {
        let _ = thread.join();
    }
    result?;
    Ok(())
}

fn parse_servers(values: &[String]) -> Result<Vec<SocketAddr>, Box<dyn Error>> {
    values
        .iter()
        .map(|value| {
            parse_server(value).map_err(|error| -> Box<dyn Error> { Box::new(error) })
        })
        .collect()
}

fn rewrite_ports(addresses: &mut [SocketAddr], port: u16) {
    for address in addresses {
        address.set_port(port);
    }
}

fn print_configuration(config: &Config, no_varlink: bool) {
    println!("configuration is valid");
    println!("upstreams: {}", config.effective_upstreams().len());
    println!("full listeners: {}", config.listeners.len());
    println!("proxy listeners: {}", config.proxy_listeners.len());
    if no_varlink {
        println!("varlink: disabled");
    } else {
        println!("varlink: {}", config.varlink_path.display());
    }
}

fn parse_options() -> Result<Option<Options>, Box<dyn Error>> {
    let mut options = Options::default();
    let mut arguments = env::args().skip(1);

    while let Some(argument) = arguments.next() {
        let (name, inline_value) = argument
            .split_once('=')
            .map_or((argument.as_str(), None), |(name, value)| (name, Some(value)));
        match name {
            "--config" => {
                options.config = option_value(inline_value, &mut arguments, name)?.into();
            }
            "--listen" => {
                options
                    .listeners
                    .push(option_value(inline_value, &mut arguments, name)?);
            }
            "--proxy-listen" => {
                options
                    .proxy_listeners
                    .push(option_value(inline_value, &mut arguments, name)?);
            }
            "--upstream" => {
                options
                    .upstreams
                    .push(option_value(inline_value, &mut arguments, name)?);
            }
            "--varlink" => {
                options.varlink = Some(option_value(inline_value, &mut arguments, name)?.into());
            }
            "--runtime-directory" => {
                options.runtime_directory =
                    Some(option_value(inline_value, &mut arguments, name)?.into());
            }
            "--workers" => {
                options.workers = Some(
                    option_value(inline_value, &mut arguments, name)?
                        .parse::<usize>()?,
                );
            }
            "--port" => {
                options.port = Some(
                    option_value(inline_value, &mut arguments, name)?.parse::<u16>()?,
                );
            }
            "--check-config" => options.check_config = true,
            "--no-stub" => options.no_stub = true,
            "--no-varlink" => options.no_varlink = true,
            "--version" => {
                println!("systemd-resolved {}", resolved::VERSION);
                return Ok(None);
            }
            "--help" | "-h" => {
                print_help();
                return Ok(None);
            }
            _ => return Err(format!("unknown option: {argument}").into()),
        }
    }
    Ok(Some(options))
}

fn option_value(
    inline: Option<&str>,
    arguments: &mut impl Iterator<Item = String>,
    option: &str,
) -> Result<String, Box<dyn Error>> {
    if let Some(value) = inline {
        if value.is_empty() {
            return Err(format!("{option} requires a value").into());
        }
        return Ok(value.to_owned());
    }
    arguments
        .next()
        .ok_or_else(|| format!("{option} requires a value").into())
}

fn print_help() {
    println!(
        "systemd-resolved {}\n\
         Usage: systemd-resolved [OPTIONS]\n\
           --config PATH\n\
           --listen ADDRESS\n\
           --proxy-listen ADDRESS\n\
           --upstream ADDRESS\n\
           --varlink PATH\n\
           --runtime-directory PATH\n\
           --workers COUNT\n\
           --port PORT\n\
           --no-stub\n\
           --no-varlink\n\
           --check-config",
        resolved::VERSION
    );
}
