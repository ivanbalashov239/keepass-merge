use std::fs::File;

use anyhow::Result;
use clap::Parser;
use keepass::{db::{Entry, Group, Node}, ChallengeResponseKey, Database, DatabaseKey};

/// Contact manager based on the KDBX4 encrypted database format
#[derive(Parser)]
#[clap(name = "keep-in-touch")]
#[clap(version = env!("CARGO_PKG_VERSION"))]
#[clap(about = "CLI tool to merge KDBX (keepass) databases", long_about = None)]
struct KeepassMerge {
    /// The path of the database file to merge to.
    destination_db: String,

    /// The path of the database file to merge from.
    source_db: String,

    /// Do not use a password to decrypt the destination database
    #[clap(long, short)]
    no_password: bool,

    /// Use the same credentials for both databases.
    #[clap(long, short)]
    same_credentials: bool,

    /// Do not save the resulting database.
    #[clap(long, short)]
    dry_run: bool,

    /// The slot number of the yubikey to decrypt the destination database
    #[arg(long)]
    slot: Option<String>,

    /// The serial number of the yubikey to decrypt the destination database
    #[arg(long)]
    serial_number: Option<u32>,

    /// The slot number of the yubikey to decrypt the source database
    #[clap(long)]
    slot_from: Option<String>,

    /// The serial number of the yubikey to decrypt the source database
    #[arg(long)]
    serial_number_from: Option<u32>,

    /// Do not use a password to decrypt the source database
    #[clap(long)]
    no_password_from: bool,

    /// Force saving the database even if warnings were generated.
    #[clap(long, short)]
    force: bool,

    /// Show verbose output with field differences for conflicting entries.
    #[clap(long, short)]
    verbose: bool,
}

fn main() -> Result<std::process::ExitCode> {
    let args = KeepassMerge::parse();

    let destination_db_path = args.destination_db;
    let source_db_path = args.source_db;

    let mut destination_db_file = File::open(&destination_db_path)?;
    let mut source_db_file = File::open(&source_db_path)?;

    let mut destination_db_key = DatabaseKey::new();

    if !args.no_password {
        let mut password_prompt = "Password for the destination database: ";
        // Use a slightly more meaningful prompt if the password is that same
        // for both databases.
        if args.same_credentials {
            password_prompt = "Password for the databases: ";
        }

        let destination_db_password =
            rpassword::prompt_password(password_prompt).expect("Could not read password from TTY");
        destination_db_key = destination_db_key.with_password(&destination_db_password);
    }

    // TODO support keyfile

    if let Some(slot) = args.slot {
        let yubikey = ChallengeResponseKey::get_yubikey(args.serial_number)?;
        destination_db_key = destination_db_key
            .with_challenge_response_key(ChallengeResponseKey::YubikeyChallenge(yubikey, slot));
    }

    if destination_db_key.is_empty() {
        return Err(anyhow::format_err!(
            "No database key was provided for destination database."
        ));
    }

    println!("Opening the destination database.");
    let mut destination_db = Database::open(&mut destination_db_file, destination_db_key.clone())?;

    let source_db = match args.same_credentials {
        true => {
            println!("Opening the source database.");
            Database::open(&mut source_db_file, destination_db_key.clone())
        }
        false => {
            let mut source_db_key = DatabaseKey::new();

            if !args.no_password_from {
                let source_db_password = rpassword::prompt_password("Password for the source database: ")
                    .expect("Could not read password from TTY");

                source_db_key = source_db_key.with_password(&source_db_password);
            }

            // TODO support keyfile

            if let Some(slot) = args.slot_from {
                let yubikey = ChallengeResponseKey::get_yubikey(args.serial_number_from)?;
                source_db_key = source_db_key
                    .with_challenge_response_key(ChallengeResponseKey::YubikeyChallenge(yubikey, slot));
            }

            if source_db_key.is_empty() {
                return Err(anyhow::format_err!(
                    "No database key was provided for source database."
                ));
            }

            println!("Opening the source database.");
            Database::open(&mut source_db_file, source_db_key)
        }
    }?;

    println!("Merging the databases.");
    let merge_result = match destination_db.merge(&source_db) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}", e);
            return Ok(std::process::ExitCode::FAILURE);
        }
    };

    for warning in &merge_result.warnings {
        println!("WARNING: {}", warning);
    }

    if args.verbose {
        let mut conflicting_uuids = std::collections::HashSet::new();
        for warning in &merge_result.warnings {
            if let Some(uuid) = extract_uuid_from_warning(warning) {
                conflicting_uuids.insert(uuid);
            }
        }

        for uuid in conflicting_uuids {
            println!("\nDetailed comparison for entry {}:", uuid);
            let dest_entry = find_entry_by_uuid(&destination_db.root, &uuid);
            let source_entry = find_entry_by_uuid(&source_db.root, &uuid);
            match (dest_entry, source_entry) {
                (Some(_de), Some(_se)) => {
                    compare_entries(_de, _se, "destination", "source");
                }
                (Some(_de), None) => {
                    println!("  Entry only in destination database.");
                }
                (None, Some(_se)) => {
                    println!("  Entry only in source database.");
                }
                (None, None) => {
                    println!("  Entry not found in either database.");
                }
            }
        }
    }

    if !args.force && !merge_result.warnings.is_empty() {
        println!("Warnings were generated by the merge operation. Not saving the database.");
        return Ok(std::process::ExitCode::FAILURE);
    }

    if merge_result.events.len() == 0 {
        println!("Nothing to merge.");
        return Ok(std::process::ExitCode::SUCCESS);
    }

    for event in merge_result.events {
        println!("{} {:?}", event.node_uuid, event.event_type);
    }
    if args.dry_run {
        println!("Running in dry-run mode. Not saving the database.");
        return Ok(std::process::ExitCode::SUCCESS);
    }

    println!("Destination database was modified. Saving the database.");
    let mut destination_db_file = File::options().write(true).open(&destination_db_path)?;
    destination_db.save(&mut destination_db_file, destination_db_key)?;
    println!("Databases were merged successfully.");

    Ok(std::process::ExitCode::SUCCESS)
}

fn find_entry_by_uuid<'a>(group: &'a Group, uuid: &str) -> Option<&'a Entry> {
    for node in &group.children {
        match node {
            Node::Group(g) => {
                if let Some(entry) = find_entry_by_uuid(g, uuid) {
                    return Some(entry);
                }
            }
            Node::Entry(e) => {
                if e.uuid.to_string() == uuid {
                    return Some(e);
                }
            }
        }
    }
    None
}

fn compare_entries(entry1: &Entry, entry2: &Entry, label1: &str, label2: &str) {
    // Print basic identifying information
    let title1 = entry1.fields.get("Title");
    let title2 = entry2.fields.get("Title");
    let url1 = entry1.fields.get("URL");
    let url2 = entry2.fields.get("URL");
    
    println!("  Entry info:");
    if let Some(title) = title1.or(title2) {
        println!("    Title: {:?}", title);
    }
    if let Some(url) = url1.or(url2) {
        println!("    URL: {:?}", url);
    }
    if !entry1.tags.is_empty() || !entry2.tags.is_empty() {
        let all_tags: std::collections::HashSet<_> = entry1.tags.iter().chain(entry2.tags.iter()).collect();
        if !all_tags.is_empty() {
            println!("    Tags: {:?}", all_tags);
        }
    }

    // Show differences
    let field_names = vec!["Title", "UserName", "URL", "Notes"];

    let mut has_differences = false;
    for field_name in field_names {
        let val1 = entry1.fields.get(field_name);
        let val2 = entry2.fields.get(field_name);
        if val1 != val2 {
            has_differences = true;
            println!("  {} differs:", field_name);
            println!("    {}: {:?}", label1, val1);
            println!("    {}: {:?}", label2, val2);
        }
    }

    if !has_differences {
        println!("  No field differences found (passwords not compared).");
    }
}

fn extract_uuid_from_warning(warning: &str) -> Option<String> {
    use regex::Regex;
    let re = Regex::new(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})").unwrap();
    re.find(warning).map(|m| m.as_str().to_string())
}
