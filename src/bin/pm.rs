/// Traffic Cypher Password Manager
///
/// Credentials are stored in ~/.traffic_cypher_vault.json, encrypted with
/// AES-256-GCM.  The vault key is derived from your master password using
/// HKDF-SHA256 — the same derivation primitive used by the key generator.

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use traffic_cypher::vault::{self, VaultEntry};

#[derive(Parser)]
#[command(
    name = "pm",
    about = "Traffic Cypher Password Manager — AES-256-GCM encrypted vault",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Add or update a password entry in the vault
    Add {
        /// Unique name for this entry (e.g. github, gmail)
        name: String,

        /// Username or email
        #[arg(short, long)]
        username: Option<String>,

        /// Password (prompted securely if omitted)
        #[arg(short, long)]
        password: Option<String>,

        /// URL associated with the entry
        #[arg(long)]
        url: Option<String>,

        /// Notes
        #[arg(long)]
        notes: Option<String>,

        /// Generate a random password instead of providing one
        #[arg(short, long)]
        generate: bool,

        /// Length of the generated password (requires --generate)
        #[arg(short, long, default_value_t = 24)]
        length: usize,
    },

    /// Retrieve and display a vault entry
    Get {
        /// Entry name to look up
        name: String,
    },

    /// List all stored entry names
    List,

    /// Delete an entry from the vault
    Delete {
        /// Entry name to delete
        name: String,
    },

    /// Generate a random password without storing it
    Generate {
        /// Password length
        #[arg(short, long, default_value_t = 24)]
        length: usize,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // `generate` needs no vault access — handle it first
    if let Commands::Generate { length } = &cli.command {
        let pwd = vault::generate_password(*length);
        println!("{}", pwd);
        return Ok(());
    }

    let master = rpassword::prompt_password("Master password: ")?;

    match cli.command {
        Commands::Add { name, username, password, url, notes, generate, length } => {
            let mut v = vault::load_vault(&master)?;

            let pwd = if generate {
                let p = vault::generate_password(length);
                println!("Generated password: {}", p);
                p
            } else if let Some(p) = password {
                p
            } else {
                let p = rpassword::prompt_password("Password: ")?;
                let confirm = rpassword::prompt_password("Confirm password: ")?;
                if p != confirm {
                    bail!("Passwords do not match");
                }
                p
            };

            let entry = VaultEntry::new(name.clone(), username, pwd, url, notes);
            v.add_or_update(entry);
            vault::save_vault(&v, &master)?;
            println!("Saved entry '{}'.", name);
        }

        Commands::Get { name } => {
            let v = vault::load_vault(&master)?;
            match v.get(&name) {
                Some(e) => print_entry(e),
                None => {
                    eprintln!("No entry found for '{}'.", name);
                    std::process::exit(1);
                }
            }
        }

        Commands::List => {
            let v = vault::load_vault(&master)?;
            if v.entries.is_empty() {
                println!("Vault is empty.");
            } else {
                println!("Vault entries ({}):", v.entries.len());
                for e in &v.entries {
                    let user = e.username.as_deref().unwrap_or("—");
                    let url = e.url.as_deref().unwrap_or("");
                    if url.is_empty() {
                        println!("  {:<20}  {}", e.name, user);
                    } else {
                        println!("  {:<20}  {:<30}  {}", e.name, user, url);
                    }
                }
            }
        }

        Commands::Delete { name } => {
            let mut v = vault::load_vault(&master)?;
            if v.delete(&name) {
                vault::save_vault(&v, &master)?;
                println!("Deleted entry '{}'.", name);
            } else {
                eprintln!("No entry found for '{}'.", name);
                std::process::exit(1);
            }
        }

        Commands::Generate { .. } => unreachable!(),
    }

    Ok(())
}

fn print_entry(e: &VaultEntry) {
    println!("Name:     {}", e.name);
    if let Some(ref u) = e.username {
        println!("Username: {}", u);
    }
    println!("Password: {}", e.password);
    if let Some(ref url) = e.url {
        println!("URL:      {}", url);
    }
    if let Some(ref notes) = e.notes {
        println!("Notes:    {}", notes);
    }
    println!(
        "Created:  {}  Updated: {}",
        fmt_unix(e.created_at),
        fmt_unix(e.updated_at)
    );
}

fn fmt_unix(ts: u64) -> String {
    let days = ts / 86400;
    let rem = ts % 86400;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;
    let (y, mo, d) = days_to_ymd(days);
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC", y, mo, d, h, m, s)
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut y = 1970u64;
    loop {
        let leap = is_leap(y);
        let dy = if leap { 366 } else { 365 };
        if days < dy {
            break;
        }
        days -= dy;
        y += 1;
    }
    let leap = is_leap(y);
    let month_days = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut mo = 1u64;
    for &md in &month_days {
        if days < md {
            break;
        }
        days -= md;
        mo += 1;
    }
    (y, mo, days + 1)
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}
