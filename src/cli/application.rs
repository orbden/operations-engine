use std::path::PathBuf;

use clap::Subcommand;

#[derive(Debug, Subcommand)]
pub enum ApplicationCommand {
    /// Install a Composer application (Statamic) into an empty site root as
    /// the site's UID: `composer create-project`, the `.env` keys for the
    /// site's address and the first administrator. The plan arrives in a
    /// root-owned request file; the operation puts no secret in argv.
    Install {
        #[arg(long = "request-file")]
        request_file: PathBuf,
        #[arg(long = "request-id")]
        request_id: String,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
}

impl ApplicationCommand {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::Install { .. } => "application.install",
        }
    }
}
