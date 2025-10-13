use std::fs::File;
use std::io::{Read, Write};

use anyhow::Result;
use clap::Parser;
use keepass::{db::{Entry, Group, Node}, ChallengeResponseKey, Database, DatabaseKey};
use uuid::Uuid;
use chrono::{DateTime, Utc};

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

    /// Threshold for automatic resolution based on modified time (default: 1M). Can be specified as seconds or with units: 1s, 1m, 1h, 1d, 1M, 1y, 1day, 1month, etc.
    #[clap(long, default_value = "1M")]
    threshold: String,

    /// Ignore threshold comparisons and use other merge strategies.
    #[clap(long)]
    ignore_threshold: bool,
}

fn main() -> Result<std::process::ExitCode> {
    let mut args = KeepassMerge::parse();

    // Parse threshold
    let threshold_seconds = match parse_threshold(&args.threshold) {
        Ok(seconds) => seconds,
        Err(e) => {
            eprintln!("Error parsing threshold: {}", e);
            return Ok(std::process::ExitCode::FAILURE);
        }
    };

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
        
        // Check if conflicts can be resolved by timestamp
        let mut auto_resolved = vec![];
        let mut still_conflicting = vec![];
        
        let mut conflicting_uuids = std::collections::HashSet::new();
        for warning in &merge_result.warnings {
            if let Some(uuid) = extract_uuid_from_warning(warning) {
                conflicting_uuids.insert(uuid);
            }
        }
        
        for uuid in &conflicting_uuids {
            if let (Some(dest_entry), Some(source_entry)) = (
                find_entry_by_uuid(&destination_db.root, uuid),
                find_entry_by_uuid(&source_db.root, uuid)
            ) {
                if !args.ignore_threshold {
                    if let Some(strategy) = resolve_conflict_by_timestamp(dest_entry, source_entry, threshold_seconds) {
                        auto_resolved.push((uuid.clone(), strategy));
                        continue;
                    }
                }
            }
            still_conflicting.push(uuid.clone());
        }
        
        // Apply automatic timestamp resolutions
        for (uuid, strategy) in &auto_resolved {
            if let (Some(_dest_entry), Some(source_entry)) = (
                find_entry_by_uuid(&destination_db.root, uuid),
                find_entry_by_uuid(&source_db.root, uuid)
            ) {
                match *strategy {
                    "prefer-destination" => {
                        println!("Entry {} resolved by timestamp: keeping destination version", uuid);
                    }
                    "prefer-source" => {
                        if let Some(dest_entry_mut) = find_entry_by_uuid_mut(&mut destination_db.root, uuid) {
                            dest_entry_mut.fields = source_entry.fields.clone();
                            dest_entry_mut.tags = source_entry.tags.clone();
                            println!("Entry {} resolved by timestamp: replaced with source version", uuid);
                        }
                    }
                    _ => {}
                }
            }
        }
        
        if !still_conflicting.is_empty() {
            println!("\n{} entries were automatically resolved by timestamp comparison.", auto_resolved.len());
            println!("{} entries still have conflicts and need manual resolution.", still_conflicting.len());
            
            // Show diffs for remaining conflicting entries
            println!("\nDetailed conflicts:");
            for uuid in &still_conflicting {
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
            
            println!("\nChoose how to resolve {} remaining conflicting entries:", still_conflicting.len());
            println!("1. Keep destination versions (discard source changes)");
            println!("2. Keep source versions (overwrite destination)");
            println!("3. Keep both versions (create duplicates)");
            println!("4. Skip all conflicts (remove conflicting entries)");
            println!("5. Cancel merge (don't save)");
            
            if !args.ignore_threshold {
                println!("\nNote: Entries with significantly different modification times (>={}s) were already resolved automatically.", args.threshold);
            }
            
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
        } else {
            println!("\nAll {} conflicts were automatically resolved by timestamp comparison!", auto_resolved.len());
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
            if let (Some(dest_entry), Some(source_entry)) = (
                find_entry_by_uuid(&destination_db.root, uuid),
                find_entry_by_uuid(&source_db.root, uuid)
            ) {
                // First, try to resolve by timestamp if not ignoring threshold
                let effective_strategy = if !args.ignore_threshold {
                    if let Some(timestamp_strategy) = resolve_conflict_by_timestamp(dest_entry, source_entry, threshold_seconds) {
                        println!("Entry {} resolved by timestamp comparison: {}", uuid, timestamp_strategy);
                        timestamp_strategy
                    } else {
                        strategy
                    }
                } else {
                    strategy
                };

                match effective_strategy {
                    "prefer-destination" => {
                        // Destination entry is already kept by merge, source is ignored
                        println!("Keeping destination version for entry {}", uuid);
                    }
                    "prefer-source" => {
                        // Replace destination entry with source entry
                        if let Some(dest_entry_mut) = find_entry_by_uuid_mut(&mut destination_db.root, uuid) {
                            // Copy source entry data to destination entry
                            dest_entry_mut.fields = source_entry.fields.clone();
                            dest_entry_mut.tags = source_entry.tags.clone();
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
                
                // Check for timestamp-based resolution
                let timestamp_suggestion = if !args.ignore_threshold {
                    resolve_conflict_by_timestamp(de, se, threshold_seconds)
                } else {
                    None
                };
                
                println!("\nChoose resolution:");
                if let Some(suggestion) = timestamp_suggestion {
                    let suggestion_text = match suggestion {
                        "prefer-destination" => "1. Keep destination version (newer)",
                        "prefer-source" => "2. Keep source version (newer)",
                        _ => "",
                    };
                    if !suggestion_text.is_empty() {
                        println!("  {} [RECOMMENDED - based on modification time]", suggestion_text);
                    }
                }
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

    // Show modification timestamps
    let time1 = parse_modified_timestamp(entry1);
    let time2 = parse_modified_timestamp(entry2);
    
    println!("  Modification times:");
    match (time1, time2) {
        (Some(t1), Some(t2)) => {
            println!("    {}: {}", label1, format_timestamp(t1));
            println!("    {}: {}", label2, format_timestamp(t2));
            
            // Calculate and show difference
            let (newer, older, newer_label, older_label) = if t1 > t2 {
                (t1, t2, label1, label2)
            } else {
                (t2, t1, label2, label1)
            };
            
            if let Some(duration) = newer.duration_since(older).ok() {
                let secs = duration.as_secs();
                let (value, unit) = format_duration(secs);
                println!("    Difference: {} is {:.1}{} newer than {}", newer_label, value, unit, older_label);
            }
        }
        (Some(t1), None) => {
            println!("    {}: {}", label1, format_timestamp(t1));
            println!("    {}: <no timestamp>", label2);
        }
        (None, Some(t2)) => {
            println!("    {}: <no timestamp>", label1);
            println!("    {}: {}", label2, format_timestamp(t2));
        }
        (None, None) => {
            println!("    No timestamps available for comparison");
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

fn format_timestamp(time: std::time::SystemTime) -> String {
    if let Ok(duration) = time.duration_since(std::time::UNIX_EPOCH) {
        if let Some(datetime) = chrono::DateTime::from_timestamp(duration.as_secs() as i64, 0) {
            datetime.format("%Y-%m-%d %H:%M:%S UTC").to_string()
        } else {
            "<invalid timestamp>".to_string()
        }
    } else {
        "<invalid timestamp>".to_string()
    }
}

fn format_duration(seconds: u64) -> (f64, &'static str) {
    if seconds < 60 {
        (seconds as f64, "s")
    } else if seconds < 3600 {
        ((seconds as f64) / 60.0, "m")
    } else if seconds < 86400 {
        ((seconds as f64) / 3600.0, "h")
    } else if seconds < 2592000 {
        ((seconds as f64) / 86400.0, "d")
    } else if seconds < 31536000 {
        ((seconds as f64) / 2592000.0, "M")
    } else {
        ((seconds as f64) / 31536000.0, "y")
    }
}

fn parse_threshold(threshold_str: &str) -> Result<u64, String> {
    let threshold_str = threshold_str.trim();
    
    // Try to parse as a plain number first (backward compatibility)
    if let Ok(seconds) = threshold_str.parse::<u64>() {
        return Ok(seconds);
    }
    
    // Parse number and unit (case-insensitive with (?i))
    let re = regex::Regex::new(r"(?i)^(\d+)([smhdMy]|second|minute|hour|day|month|year|seconds|minutes|hours|days|months|years)?$").unwrap();
    
    if let Some(captures) = re.captures(threshold_str) {
        let number: u64 = captures[1].parse().map_err(|_| "Invalid number")?;
        let unit = captures.get(2).map(|m| m.as_str().to_lowercase()).unwrap_or_else(|| "s".to_string());
        
        let multiplier = match unit.as_str() {
            "s" | "second" | "seconds" => 1,
            "m" | "minute" | "minutes" => 60,
            "h" | "hour" | "hours" => 3600,
            "d" | "day" | "days" => 86400,
            "M" | "month" | "months" => 2592000, // 30 days
            "y" | "year" | "years" => 31536000, // 365 days
            _ => return Err(format!("Unknown time unit: {}", unit)),
        };
        
        Ok(number * multiplier)
    } else {
        Err(format!("Invalid threshold format: {}. Expected format: <number>[<unit>], where unit can be s/m/h/d/M/y or second/minute/hour/day/month/year", threshold_str))
    }
}

fn parse_modified_timestamp(entry: &Entry) -> Option<std::time::SystemTime> {
    // First try to get the timestamp from the times field
    if let Some(mod_time) = entry.times.times.get("LastModificationTime") {
        // Convert NaiveDateTime to SystemTime
        // KeePass stores times as local time, but we'll assume they're close enough to UTC for comparison
        // Convert to UTC assuming the stored time is in UTC
        let datetime_utc = DateTime::<Utc>::from_naive_utc_and_offset(*mod_time, Utc);
        Some(datetime_utc.into())
    } else {
        // Fallback to fields (for backward compatibility or if times field is not populated)
        let possible_fields = ["LastModificationTime", "Modified", "Times.LastModificationTime"];
        
        for field_name in &possible_fields {
            if let Some(value) = entry.fields.get(*field_name) {
                // Convert Value to string
                let value_str: &str = match value {
                    keepass::db::Value::Unprotected(s) => s,
                    keepass::db::Value::Protected(p) => {
                        std::str::from_utf8(p.unsecure()).unwrap_or("")
                    },
                    keepass::db::Value::Bytes(_) => continue, // Skip binary fields
                };
                
                // Try parsing as Unix timestamp first
                if let Ok(timestamp) = value_str.parse::<i64>() {
                    if timestamp > 0 {
                        return Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(timestamp as u64));
                    }
                }
                
                // Try parsing as ISO 8601 datetime string
                if let Ok(dt) = DateTime::parse_from_rfc3339(value_str) {
                    return Some(dt.with_timezone(&Utc).into());
                }
                if let Ok(dt) = DateTime::parse_from_rfc2822(value_str) {
                    return Some(dt.with_timezone(&Utc).into());
                }
            }
        }
        
        None
    }
}

fn resolve_conflict_by_timestamp<'a>(dest_entry: &'a Entry, source_entry: &'a Entry, threshold_seconds: u64) -> Option<&'static str> {
    let dest_time = parse_modified_timestamp(dest_entry);
    let source_time = parse_modified_timestamp(source_entry);
    
    match (dest_time, source_time) {
        (Some(dt), Some(st)) => {
            let duration = if dt > st {
                dt.duration_since(st).ok()?
            } else {
                st.duration_since(dt).ok()?
            };
            
            if duration.as_secs() >= threshold_seconds {
                if dt > st {
                    Some("prefer-destination")
                } else {
                    Some("prefer-source")
                }
            } else {
                None
            }
        }
        _ => None,
    }
}
