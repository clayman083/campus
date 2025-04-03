use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use clap::{Parser, Subcommand, builder::BoolishValueParser};

use protocols::passport::RegisterRequest;
use protocols::passport::auth_client::AuthClient;

#[derive(Debug, Parser)]
#[command(name = "passport")]
#[command(version, about = "Passport control CLI", long_about = None)]
struct Cli {
    #[arg(
        long,
        default_value_t = false,
        value_parser = BoolishValueParser::new(),
        global = true,
        env = "DEBUG",
        help = "Enable debug mode"
    )]
    debug: bool,

    #[arg(
        long,
        default_value_t = String::from("http://localhost:5000"),
        global = true,
        env = "PASSPORT_HOST",
        help = "Specify the host of the passport service"
    )]
    host: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(arg_required_else_help = true)]
    Register {
        #[arg(short, long, help = "Specify the username")]
        username: String,
        #[arg(short, long, help = "Specify the password")]
        password: String,
    },

    Login {
        #[arg(short, long)]
        username: String,
        #[arg(short, long)]
        password: String,
    },

    Tokens {
        #[command(subcommand)]
        command: Tokens,
    },
}

#[derive(Debug, Subcommand)]
enum Tokens {
    List,

    #[command(arg_required_else_help = true)]
    Issue {
        #[arg(long)]
        name: String,
    },

    Revoke {
        #[arg(long)]
        token: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!("{}=debug,tower_http=trace", env!("CARGO_CRATE_NAME")).into()
            }),
        )
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .init();

    let args = Cli::parse();

    if args.debug {
        tracing::info!("Debug mode enabled");
    }

    match args.command {
        Commands::Register { username, password } => {
            let mut client = AuthClient::connect("http://127.0.0.1:5000").await?;

            let request = tonic::Request::new(RegisterRequest { username, password });

            let response = client.register(request).await?;
            let user = response.into_inner();

            tracing::info!("User registered: {:?}", user);
        }

        Commands::Login { username, password } => {
            return Err("Not implemented".into());
        }

        Commands::Tokens { command } => match command {
            Tokens::List => {
                return Err("Not implemented".into());
            }

            Tokens::Issue { name } => {
                return Err("Not implemented".into());
            }

            Tokens::Revoke { token } => {
                return Err("Not implemented".into());
            }
        },
    }

    Ok(())
}
