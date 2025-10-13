use std::fs::File;
use std::io::{Read, Write};

use anyhow::Result;
use clap::Parser;
use keepass::{db::{Entry, Group, Node}, ChallengeResponseKey, Database, DatabaseKey};
use uuid::Uuid;

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

    /// Interactive mode: resolve conflicts manually.
    #[clap(long, short)]
    interactive: bool,

    /// Automatically keep destination version for all conflicts.
    #[clap(long)]
    prefer_destination: bool,

    /// Automatically keep source version for all conflicts.
    #[clap(long)]
    prefer_source: bool,

    /// Automatically keep both versions for all conflicts (default behavior).
    #[clap(long)]
    keep_both: bool,

    /// Automatically skip all conflicting entries.
    #[clap(long)]
    skip_conflicts: bool,

    /// Automatically save the database without asking for confirmation.
    #[clap(long, short)]
    yes: bool,
}

fn main() -> Result<std::process::ExitCode> {
    let mut args = KeepassMerge::parse();

    // Validate merge strategy options are mutually exclusive
    let strategy_count = args.prefer_destination as u8 + args.prefer_source as u8 + args.keep_both as u8 + args.skip_conflicts as u8;
    if strategy_count > 1 {
        return Err(anyhow::format_err!(
            "Merge strategy options are mutually exclusive. Choose only one of: --prefer-destination, --prefer-source, --keep-both, --skip-conflicts"
        ));
    }
    if args.interactive && strategy_count > 0 {
        return Err(anyhow::format_err!(
            "Cannot use both interactive mode (-i) and automatic merge strategies"
        ));
    }

    let destination_db_path = args.destination_db;
    let source_db_path = args.source_db;

    // Read and store the original destination database content for integrity checking
    println!("Reading original destination database...");
    let mut original_db_file = File::open(&destination_db_path)?;
    let mut original_db_content = Vec::new();
    original_db_file.read_to_end(&mut original_db_content)?;

    // Create a temporary copy of the destination database for safe operations
    println!("Creating temporary copy of destination database...");
    let temp_destination_path = create_temp_db_copy(&destination_db_path)
        .map_err(|e| anyhow::format_err!("Failed to create temporary copy of destination database: {}", e))?;

    let mut destination_db_file = File::open(&temp_destination_path)?;
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

    // Handle conflicts when no strategy is specified
    if !args.interactive && !args.prefer_destination && !args.prefer_source && !args.keep_both && !args.skip_conflicts && !merge_result.warnings.is_empty() {
        println!("\nConflicts detected during merge:");
        println!("  Destination database: {}", destination_db_path);
        println!("  Source database: {}", source_db_path);
        
        // Show diffs for all conflicting entries
        let mut conflicting_uuids = std::collections::HashSet::new();
        for warning in &merge_result.warnings {
            if let Some(uuid) = extract_uuid_from_warning(warning) {
                conflicting_uuids.insert(uuid);
            }
        }
        
        println!("\nDetailed conflicts:");
        for uuid in &conflicting_uuids {
            println!("\n--- Entry {} ---", uuid);
            let dest_entry = find_entry_by_uuid(&destination_db.root, uuid);
            let source_entry = find_entry_by_uuid(&source_db.root, uuid);
            match (dest_entry, source_entry) {
                (Some(de), Some(se)) => {
                    compare_entries(de, se, "destination", "source");
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
        
        println!("\nChoose how to resolve {} conflicting entries:", merge_result.warnings.len() / 2);
        println!("1. Keep destination versions (discard source changes)");
        println!("2. Keep source versions (overwrite destination)");
        println!("3. Keep both versions (create duplicates)");
        println!("4. Skip all conflicts (remove conflicting entries)");
        println!("5. Cancel merge (don't save)");
        
        let choice = get_user_choice_with_range(5);
        match choice {
            1 => {
                args.prefer_destination = true;
                println!("Applying: Keep destination versions");
            }
            2 => {
                args.prefer_source = true;
                println!("Applying: Keep source versions");
            }
            3 => {
                args.keep_both = true;
                println!("Applying: Keep both versions");
            }
            4 => {
                args.skip_conflicts = true;
                println!("Applying: Skip all conflicts");
            }
            5 => {
                println!("Merge cancelled by user.");
                // Clean up temp file
                let _ = std::fs::remove_file(&temp_destination_path);
                return Ok(std::process::ExitCode::SUCCESS);
            }
            _ => {
                println!("Invalid choice, using default: Keep both versions");
                args.keep_both = true;
            }
        }
    }

    // Apply conflict resolution strategies for conflicting entries
    if args.prefer_destination || args.prefer_source || args.keep_both || args.skip_conflicts {
        let strategy = if args.prefer_destination {
            "prefer-destination"
        } else if args.prefer_source {
            "prefer-source"
        } else if args.keep_both {
            "keep-both"
        } else {
            "skip-conflicts"
        };
        
        println!("Applying conflict resolution strategy: {}", strategy);
        
        let mut conflicting_uuids = std::collections::HashSet::new();
        for warning in &merge_result.warnings {
            if let Some(uuid) = extract_uuid_from_warning(warning) {
                conflicting_uuids.insert(uuid);
            }
        }

        for uuid in &conflicting_uuids {
            if let Some(source_entry) = find_entry_by_uuid(&source_db.root, uuid) {
                match strategy {
                    "prefer-destination" => {
                        // Destination entry is already kept by merge, source is ignored
                        println!("Keeping destination version for entry {}", uuid);
                    }
                    "prefer-source" => {
                        // Replace destination entry with source entry
                        if let Some(dest_entry) = find_entry_by_uuid_mut(&mut destination_db.root, uuid) {
                            // Copy source entry data to destination entry
                            dest_entry.fields = source_entry.fields.clone();
                            dest_entry.tags = source_entry.tags.clone();
                            // Keep the same UUID and other metadata
                            println!("Replaced destination entry {} with source version", uuid);
                        }
                    }
                    "keep-both" => {
                        // Clone the source entry with a new UUID and add it
                        let mut cloned_entry = source_entry.clone();
                        cloned_entry.uuid = Uuid::new_v4();
                        // Add to the root group for simplicity
                        destination_db.root.children.push(keepass::db::Node::Entry(cloned_entry));
                        println!("Added cloned source entry for {} with new UUID", uuid);
                    }
                    "skip-conflicts" => {
                        // Remove the conflicting entry that was added by merge
                        let _ = find_entry_location_mut(&mut destination_db.root, uuid);
                        println!("Skipped conflicting entry {}", uuid);
                    }
                    _ => {}
                }
            }
        }
    }

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

    if args.interactive && !merge_result.warnings.is_empty() {
        println!("\nInteractive mode: {} entries have conflicts.", merge_result.warnings.len() / 2); // Rough estimate, warnings come in pairs
        
        let mut conflicting_uuids = std::collections::HashSet::new();
        for warning in &merge_result.warnings {
            if let Some(uuid) = extract_uuid_from_warning(warning) {
                conflicting_uuids.insert(uuid);
            }
        }

        for uuid in &conflicting_uuids {
            println!("\n--- Entry {} ---", uuid);
            let dest_entry = find_entry_by_uuid(&destination_db.root, uuid);
            let source_entry = find_entry_by_uuid(&source_db.root, uuid);
            
            if let (Some(de), Some(se)) = (dest_entry, source_entry) {
                compare_entries(de, se, "destination", "source");
                
                println!("\nChoose resolution:");
                println!("1. Keep destination version");
                println!("2. Keep source version");
                println!("3. Keep both versions (default merge behavior)");
                println!("4. Skip this entry");
                
                let choice = get_user_choice();
                match choice {
                    1 => println!("Keeping destination version for entry {}", uuid),
                    2 => println!("Keeping source version for entry {}", uuid),
                    3 => println!("Keeping both versions for entry {}", uuid),
                    4 => println!("Skipping entry {}", uuid),
                    _ => println!("Invalid choice, keeping both versions"),
                }
            }
        }
    }

    if (args.interactive || args.prefer_destination || args.prefer_source || args.keep_both || args.skip_conflicts) && !merge_result.warnings.is_empty() {
        if !args.yes {
            println!("\nConflict resolution complete.");
            println!("Do you want to save the database? (y/N): ");
            
            let save_choice = get_yes_no_choice();
            if !save_choice {
                println!("Not saving the database.");
                // Clean up temp file
                let _ = std::fs::remove_file(&temp_destination_path);
                return Ok(std::process::ExitCode::SUCCESS);
            }
        } else {
            println!("\nConflict resolution complete. Saving database (--yes flag set).");
        }
    } else if !args.force && !merge_result.warnings.is_empty() {
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
        // Clean up temp file
        let _ = std::fs::remove_file(&temp_destination_path);
        return Ok(std::process::ExitCode::SUCCESS);
    }

    // Check if the original destination file is still the same before saving
    println!("Checking if destination database is unchanged...");
    let mut current_original_file = File::open(&destination_db_path)?;
    let mut current_original_content = Vec::new();
    current_original_file.read_to_end(&mut current_original_content)?;
    
    if current_original_content != original_db_content {
        println!("ERROR: The original destination database has been modified since the merge started!");
        println!("For safety, the merge operation has been cancelled.");
        println!("Please restart the merge with the current database state.");
        // Clean up temp file
        let _ = std::fs::remove_file(&temp_destination_path);
        return Ok(std::process::ExitCode::FAILURE);
    } else {
        println!("Original database is unchanged. Proceeding with save.");
    }

    println!("Destination database was modified. Saving the database.");
    
    // Save to the temporary file first
    let mut temp_db_file = File::options().write(true).open(&temp_destination_path)?;
    destination_db.save(&mut temp_db_file, destination_db_key)?;
    
    // Now replace the original with the modified temp file
    match replace_original_with_temp(&destination_db_path, &temp_destination_path) {
        Ok(_) => {
            println!("Databases were merged successfully.");
            Ok(std::process::ExitCode::SUCCESS)
        }
        Err(e) => {
            println!("ERROR: Failed to replace original database with merged version: {}", e);
            println!("The merged database is saved as: {}", temp_destination_path);
            println!("You can manually replace the original file if needed.");
            Ok(std::process::ExitCode::FAILURE)
        }
    }
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

fn find_entry_by_uuid_mut<'a>(group: &'a mut Group, uuid: &str) -> Option<&'a mut Entry> {
    for node in &mut group.children {
        match node {
            Node::Group(g) => {
                if let Some(entry) = find_entry_by_uuid_mut(g, uuid) {
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

fn find_entry_location_mut(group: &mut Group, uuid: &str) -> Option<usize> {
    for (index, node) in group.children.iter_mut().enumerate() {
        match node {
            Node::Group(g) => {
                if let Some(child_index) = find_entry_location_mut(g, uuid) {
                    // Remove from child group
                    g.children.remove(child_index);
                    return Some(index); // Return something to indicate we found and removed it
                }
            }
            Node::Entry(e) => {
                if e.uuid.to_string() == uuid {
                    return Some(index);
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
    let username1 = entry1.fields.get("UserName");
    let username2 = entry2.fields.get("UserName");
    
    println!("  Entry info:");
    if let Some(title) = title1.or(title2) {
        println!("    Title: {:?}", title);
    }
    if let Some(username) = username1.or(username2) {
        println!("    Username: {:?}", username);
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

fn get_user_choice() -> u32 {
    get_user_choice_with_range(4)
}

fn get_user_choice_with_range(max_choice: u32) -> u32 {
    use std::io::{self, Write};
    
    loop {
        print!("Enter your choice (1-{}): ", max_choice);
        io::stdout().flush().unwrap();
        
        let mut input = String::new();
        match io::stdin().read_line(&mut input) {
            Ok(_) => {
                let trimmed = input.trim();
                if trimmed.is_empty() && max_choice >= 3 {
                    return 3; // Default choice for global conflicts
                }
                match trimmed.parse::<u32>() {
                    Ok(choice) if choice >= 1 && choice <= max_choice => return choice,
                    _ => println!("Please enter a number between 1 and {}.", max_choice),
                }
            }
            Err(_) => {
                println!("Error reading input, using default (3).");
                return 3;
            }
        }
    }
}

fn get_yes_no_choice() -> bool {
    use std::io::{self};
    
    let mut input = String::new();
    match io::stdin().read_line(&mut input) {
        Ok(_) => {
            let input = input.trim().to_lowercase();
            input == "y" || input == "yes"
        }
        Err(_) => false,
    }
}

fn create_temp_db_copy(original_path: &str) -> Result<String, std::io::Error> {
    let temp_path = format!("{}.tmp", original_path);
    
    // Read the original file
    let mut original_file = File::open(original_path)?;
    let mut buffer = Vec::new();
    original_file.read_to_end(&mut buffer)?;
    
    // Write to temporary file
    let mut temp_file = File::create(&temp_path)?;
    temp_file.write_all(&buffer)?;
    temp_file.flush()?;
    
    Ok(temp_path)
}

fn replace_original_with_temp(original_path: &str, temp_path: &str) -> Result<(), std::io::Error> {
    // Replace original with temp
    // std::fs::remove_file(original_path)?;
    std::fs::rename(temp_path, original_path)?;
    Ok(())
}
