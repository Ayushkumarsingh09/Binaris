use clap::{Parser, Subcommand};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "binaris", about = "Binaris CLI")]
struct Cli {
    #[arg(long, env = "BINARIS_API_URL", default_value = "http://127.0.0.1:8080")]
    api: String,
    #[arg(long, env = "BINARIS_TOKEN")]
    token: Option<String>,
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Authenticate and print an exportable token
    Login {
        #[arg(long, env = "BINARIS_EMAIL")]
        email: String,
        #[arg(long, env = "BINARIS_PASSWORD")]
        password: String,
    },
    Projects,
    Analyze {
        project_id: Uuid,
        file: PathBuf,
    },
    Get {
        analysis_id: Uuid,
    },
    Chat {
        analysis_id: Uuid,
        message: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Commands::Login { email, password } => {
            let token = reqwest_login(&cli.api, &email, &password).await?;
            println!("export BINARIS_TOKEN={token}");
            return Ok(());
        }
        _ => {}
    }

    let token = cli
        .token
        .ok_or_else(|| anyhow::anyhow!("BINARIS_TOKEN or --token required"))?;
    let client = binaris_sdk::BinarisClient::new(&cli.api, token);

    match cli.cmd {
        Commands::Login { .. } => unreachable!(),
        Commands::Projects => {
            let projects = client.list_projects().await?;
            println!("{}", serde_json::to_string_pretty(&projects)?);
        }
        Commands::Analyze { project_id, file } => {
            let bytes = std::fs::read(&file)?;
            let name = file
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("upload.bin");
            let report = client.upload(project_id, name, bytes).await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Commands::Get { analysis_id } => {
            let report = client.get_analysis(analysis_id).await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Commands::Chat {
            analysis_id,
            message,
        } => {
            let answer = client.chat(analysis_id, message).await?;
            println!("{}", serde_json::to_string_pretty(&answer)?);
        }
    }
    Ok(())
}

async fn reqwest_login(api: &str, email: &str, password: &str) -> anyhow::Result<String> {
    let client = reqwest::Client::new();
    let res = client
        .post(format!("{}/v1/auth/login", api.trim_end_matches('/')))
        .json(&serde_json::json!({ "email": email, "password": password }))
        .send()
        .await?;
    if !res.status().is_success() {
        anyhow::bail!(res.text().await.unwrap_or_default());
    }
    let v: serde_json::Value = res.json().await?;
    Ok(v["token"].as_str().unwrap_or_default().to_string())
}
