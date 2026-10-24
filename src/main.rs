use std::path::PathBuf;
use std::process::ExitCode;

use tracing_subscriber::EnvFilter;

const USAGE: &str = "usage: lokaj <config.toml>   (or set LOKAJ_CONFIG)";

fn main() -> ExitCode {
    let filter = EnvFilter::try_from_env("LOKAJ_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    let subscriber = tracing_subscriber::fmt().with_env_filter(filter);
    if std::env::var("LOKAJ_LOG_FORMAT").is_ok_and(|format| format == "json") {
        subscriber.json().init();
    } else {
        subscriber.init();
    }

    let path = match std::env::args_os()
        .nth(1)
        .or_else(|| std::env::var_os("LOKAJ_CONFIG"))
    {
        Some(path) if path != "--help" && path != "-h" => PathBuf::from(path),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    let config = match lokaj::config::Config::load(&path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("lokaj: {error}");
            return ExitCode::from(2);
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("lokaj: cannot start the runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(lokaj::app::run(config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "lokaj failed");
            ExitCode::FAILURE
        }
    }
}
