fn main() {
    // RUST_LOG=nfse=info logs when the token signs the TLS handshake.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("off")).init();
    if let Err(e) = nfse::cli::main() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
