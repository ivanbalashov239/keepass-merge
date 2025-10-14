use std::fs::File;
use std::io::{Read, Write};

use anyhow::Result;
use clap::Parser;
use keepass::{db::{Entry, Group, Node}, ChallengeResponseKey, Database, DatabaseKey};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use log;

/// Contact manager based on the KDBX4 encrypted database format
#[derive(Parser)]
#[clap(name = "keep-in-touch")]
#[clap(version = env!("CARGO_PKG_VERSION"))]
#[clap(about = "CLI tool to merge KDBX (keepass) databases", long_about = None)]
struct KeepassMerge {
    /// The path of the database file to merge to.
    destination_db: String,

    /// The path(s) of the database file(s) to merge from.
    source_db: Vec<String>,

    /// Do not use a password to decrypt the destination database
    #[clap(long, short)]
    no_password: bool,

    /// Password for the destination database (for testing). Use "-" to read from stdin.
    #[clap(long)]
    password: Option<String>,

    /// Password for the source database (for testing). Use "-" to read from stdin.
    #[clap(long)]
    source_password: Option<String>,

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
    no_source_password: bool,

    /// Force saving the database even if warnings were generated.
    #[clap(long, short)]
    force: bool,

    /// Show verbose output with field differences for conflicting entries. Use -vv for debug logging.
    #[clap(long, short, action = clap::ArgAction::Count)]
    verbose: u8,

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

/// Read password from stdin if password argument is "-", otherwise return the password as-is
fn resolve_password(password_arg: &str) -> Result<String> {
    if password_arg == "-" {
        let mut buffer = String::new();
        std::io::stdin().read_line(&mut buffer)?;
        // Remove trailing newline if present
        Ok(buffer.trim_end().to_string())
    } else {
        Ok(password_arg.to_string())
    }
}

fn merge_single_source(args: &mut KeepassMerge, source_db_path: &str) -> Result<std::process::ExitCode> {

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

    let destination_db_path = args.destination_db.clone();
    let source_db_path = source_db_path.to_string();
    let destination_path = std::path::Path::new(&destination_db_path);
    let temp_path = destination_path.with_file_name(format!(".tmpkdbx.{}", destination_path.file_name().unwrap().to_string_lossy())).to_string_lossy().to_string();

    // Helper function to clean up temp file
    let cleanup_temp_file = || {
        let _ = std::fs::remove_file(&temp_path);
    };

    // Read and store the original destination database content for integrity checking
    println!("Reading original destination database...");
    let mut original_db_file = File::open(&destination_db_path)?;
    let mut original_db_content = Vec::new();
    original_db_file.read_to_end(&mut original_db_content)?;

    // Create a temporary copy of the destination database for safe operations
    println!("Creating temporary copy of destination database...");
    let temp_destination_path = create_temp_db_copy(&temp_path, &destination_db_path)
        .map_err(|e| anyhow::format_err!("Failed to create temporary copy of destination database: {}", e))?;

    let mut destination_db_file = File::open(&temp_destination_path)?;
    let mut source_db_file = File::open(&source_db_path)?;

    let mut destination_db_key = DatabaseKey::new();

    if !args.no_password {
        let destination_db_password = if let Some(ref pwd) = args.password {
            resolve_password(pwd)?
        } else {
            // Fallback to interactive prompt if no password provided
            rpassword::prompt_password("Password for the destination database: ")
                .expect("Could not read password from TTY")
        };
        destination_db_key = destination_db_key.with_password(&destination_db_password);
    }

    // TODO support keyfile

    if let Some(slot) = &args.slot {
        let yubikey = ChallengeResponseKey::get_yubikey(args.serial_number)?;
        destination_db_key = destination_db_key
            .with_challenge_response_key(ChallengeResponseKey::YubikeyChallenge(yubikey, slot.clone()));
    }

    if destination_db_key.is_empty() {
        cleanup_temp_file();
        return Err(anyhow::format_err!(
            "No database key was provided for destination database."
        ));
    }

    println!("Opening the destination database.");
    let mut destination_db = match Database::open(&mut destination_db_file, destination_db_key.clone()) {
        Ok(db) => db,
        Err(e) => {
            cleanup_temp_file();
            return Err(e.into());
        }
    };

    let mut source_db = match args.same_credentials {
        true => {
            println!("Opening the source database.");
            match Database::open(&mut source_db_file, destination_db_key.clone()) {
                Ok(db) => db,
                Err(e) => {
                    cleanup_temp_file();
                    return Err(e.into());
                }
            }
        }
        false => {
            let mut source_db_key = DatabaseKey::new();

            if !args.no_source_password {
                let source_db_password = if let Some(ref pwd) = args.source_password {
                    resolve_password(pwd)?
                } else if args.same_credentials {
                    // Use the same password as destination (already resolved)
                    args.password.as_ref().unwrap().clone()
                } else {
                    rpassword::prompt_password("Password for the source database: ")
                        .expect("Could not read password from TTY")
                };

                source_db_key = source_db_key.with_password(&source_db_password);
            }

            // TODO support keyfile

            if let Some(slot) = &args.slot_from {
                let yubikey = ChallengeResponseKey::get_yubikey(args.serial_number_from)?;
                source_db_key = source_db_key
                    .with_challenge_response_key(ChallengeResponseKey::YubikeyChallenge(yubikey, slot.clone()));
            }

            if source_db_key.is_empty() {
                cleanup_temp_file();
                return Err(anyhow::format_err!(
                    "No database key was provided for source database."
                ));
            }

            println!("Opening the source database.");
            match Database::open(&mut source_db_file, source_db_key) {
                Ok(db) => db,
                Err(e) => {
                    cleanup_temp_file();
                    return Err(e.into());
                }
            }
        }
    };

    if args.verbose > 0 {
        let dest_count = count_entries(&destination_db.root);
        let source_count = count_entries(&source_db.root);
        println!("Destination database has {} entries.", dest_count);
        println!("Source database has {} entries.", source_count);
    }
    
    // Collect original timestamps before merge for conflict resolution
    let mut original_timestamps = std::collections::HashMap::new();
    collect_original_timestamps(&destination_db.root, &source_db.root, &mut original_timestamps);
    
    // For conflict resolution strategies that need original entries, collect them
    let mut original_destination_entries = std::collections::HashMap::new();
    collect_original_entries(&destination_db.root, &source_db.root, &mut original_destination_entries);
    
    if args.verbose > 0 {
        println!("Analyzed {} entries for timestamp information.", original_timestamps.len());
        println!("Backed up {} destination entries for conflict resolution.", original_destination_entries.len());
    }
    
    let merge_result = match destination_db.merge(&source_db) {
        Ok(r) => r,
        Err(e) => {
            let error_msg = format!("{}", e);
            // Handle the case where groups have diverged with same timestamp
            if error_msg.contains("GroupModificationTimeNotUpdated") || error_msg.contains("have the same modification time but have diverged") {
                eprintln!("Detected groups with same modification time but diverged content.");
                eprintln!("Attempting to fix by adjusting source group timestamps...");
                
                // Find groups with same UUID and timestamp but different content
                fix_diverged_groups(&mut source_db, &destination_db);
                
                // Retry the merge
                match destination_db.merge(&source_db) {
                    Ok(r) => r,
                    Err(e2) => {
                        eprintln!("Merge failed even after fixing timestamps: {}", e2);
                        cleanup_temp_file();
                        return Ok(std::process::ExitCode::FAILURE);
                    }
                }
            } else {
                eprintln!("{}", e);
                cleanup_temp_file();
                return Ok(std::process::ExitCode::FAILURE);
            }
        }
    };

    if args.verbose > 0 {
        println!("Merge completed with {} warnings.", merge_result.warnings.len());
    }

    // Handle conflicts when no strategy is specified
    let mut still_conflicting = vec![];
    let mut auto_resolved_count = 0;
    if !args.prefer_destination && !args.prefer_source && !args.keep_both && !args.skip_conflicts && !merge_result.warnings.is_empty() {
        println!("\nConflicts detected during merge:");
        println!("  Destination database: {}", destination_db_path);
        println!("  Source database: {}", source_db_path);
        
        // Check if conflicts can be resolved by timestamp
        let mut auto_resolved = vec![];
        
        let mut conflicting_uuids = std::collections::HashSet::new();
        for warning in &merge_result.warnings {
            if let Some(uuid) = extract_uuid_from_warning(warning) {
                conflicting_uuids.insert(uuid);
            }
        }
        
        for uuid in &conflicting_uuids {
            if let (Some(_dest_entry), Some(_source_entry)) = (
                find_entry_by_uuid(&destination_db.root, uuid),
                find_entry_by_uuid(&source_db.root, uuid)
            ) {
                if !args.ignore_threshold {
                    if let Some((dest_time, source_time)) = original_timestamps.get(uuid) {
                        if let Some(strategy) = resolve_conflict_by_timestamp(*dest_time, *source_time, threshold_seconds) {
                            auto_resolved.push((uuid.clone(), strategy));
                            continue;
                        }
                    }
                }
            }
            still_conflicting.push(uuid.clone());
        }
        
        // Apply automatic timestamp resolutions
        if !auto_resolved.is_empty() {
            println!("Starting timestamp-based conflict resolution for {} entries...", auto_resolved.len());
            auto_resolved_count = auto_resolved.len();
        }
        for (uuid, strategy) in &auto_resolved {
            let dest_entry = find_entry_by_uuid(&destination_db.root, &uuid).cloned();
            let source_entry = find_entry_by_uuid(&source_db.root, &uuid).cloned();
            
            if let (Some(dest_entry), Some(source_entry)) = (dest_entry, source_entry) {
                // Show diff before resolution
                println!("\n--- Diff before resolution for entry {} ---", uuid);
                compare_entries(&dest_entry, &source_entry, "destination", "source");
                
                match *strategy {
                    "prefer-destination" => {
                        // For prefer-destination, restore the original destination entry fields
                        // (the merge has already combined entries, so we need to undo that)
                        if let Some(original_dest_entry) = original_destination_entries.get(uuid) {
                            if let Some(dest_entry_mut) = find_entry_by_uuid_mut(&mut destination_db.root, &uuid) {
                                // Restore the original fields, tags, etc.
                                dest_entry_mut.fields = original_dest_entry.fields.clone();
                                dest_entry_mut.tags = original_dest_entry.tags.clone();
                                dest_entry_mut.autotype = original_dest_entry.autotype.clone();
                                dest_entry_mut.times = original_dest_entry.times.clone();
                                dest_entry_mut.custom_data = original_dest_entry.custom_data.clone();
                                dest_entry_mut.icon_id = original_dest_entry.icon_id;
                                dest_entry_mut.custom_icon_uuid = original_dest_entry.custom_icon_uuid;
                                dest_entry_mut.foreground_color = original_dest_entry.foreground_color.clone();
                                dest_entry_mut.background_color = original_dest_entry.background_color.clone();
                                dest_entry_mut.override_url = original_dest_entry.override_url.clone();
                                dest_entry_mut.quality_check = original_dest_entry.quality_check;
                                dest_entry_mut.history = original_dest_entry.history.clone();
                                println!("Keeping destination version for entry {}", uuid);
                            } else {
                                println!("Warning: Could not find entry {} to restore original version", uuid);
                            }
                        } else {
                            println!("Warning: No original destination entry found for {}", uuid);
                        }
                    }
                    "prefer-source" => {
                        if let Some(dest_entry_mut) = find_entry_by_uuid_mut(&mut destination_db.root, &uuid) {
                            add_entry_to_history(dest_entry_mut, &dest_entry, "Destination entry replaced");
                            dest_entry_mut.fields = source_entry.fields.clone();
                            dest_entry_mut.tags = source_entry.tags.clone();
                            println!("Entry {} resolved by timestamp: replaced with source version", uuid);
                            
                            // Show diff between final winning entry and losing entry
                            if let Some(final_dest_entry) = find_entry_by_uuid(&destination_db.root, &uuid) {
                                println!("\n--- Diff after resolution for entry {} ---", uuid);
                                compare_entries(final_dest_entry, &dest_entry, "source (final)", "destination (lost)");
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        
        if !still_conflicting.is_empty() {
            println!("\n{} entries were automatically resolved by timestamp comparison.", auto_resolved.len());
            println!("{} entries still have conflicts and need manual resolution.", still_conflicting.len());
            
            // Add source entries to history for conflicts that will keep destination by default
            for uuid in &still_conflicting {
                if let (Some(_dest_entry), Some(source_entry)) = (
                    find_entry_by_uuid(&destination_db.root, uuid),
                    find_entry_by_uuid(&source_db.root, uuid)
                ) {
                    if let Some(dest_entry_mut) = find_entry_by_uuid_mut(&mut destination_db.root, uuid) {
                        add_entry_to_history(dest_entry_mut, &source_entry, "Source entry discarded");
                    }
                }
            }
            
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
            
            if args.interactive {
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
                        cleanup_temp_file();
                        return Ok(std::process::ExitCode::FAILURE);
                    }
                    _ => {
                        println!("Invalid choice, using default: Keep both versions");
                        args.keep_both = true;
                    }
                }
            } else {
                // In non-interactive mode
                if args.force {
                    println!("Proceeding with default conflict resolution (keep both versions) due to --force.");
                    args.keep_both = true;
                } else {
                    eprintln!("{} entries still have conflicts and require manual resolution.", still_conflicting.len());
                    eprintln!("Use --prefer-destination, --prefer-source, --keep-both, --skip-conflicts, -i (interactive), or --force.");
                    cleanup_temp_file();
                    return Ok(std::process::ExitCode::FAILURE);
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
            let dest_entry = find_entry_by_uuid(&destination_db.root, uuid).cloned();
            let source_entry = find_entry_by_uuid(&source_db.root, uuid).cloned();
            
            if let (Some(dest_entry), Some(source_entry)) = (dest_entry, source_entry) {
                // First, try to resolve by timestamp if not ignoring threshold
                let effective_strategy = if !args.ignore_threshold {
                    if let Some(timestamp_strategy) = resolve_conflict_by_timestamp_entries(&dest_entry, &source_entry, threshold_seconds) {
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
                        // For prefer-destination, restore the original destination entry fields
                        // (the merge has already combined entries, so we need to undo that)
                        if let Some(original_dest_entry) = original_destination_entries.get(uuid) {
                            if let Some(dest_entry_mut) = find_entry_by_uuid_mut(&mut destination_db.root, &uuid) {
                                // Restore the original fields, tags, etc.
                                dest_entry_mut.fields = original_dest_entry.fields.clone();
                                dest_entry_mut.tags = original_dest_entry.tags.clone();
                                dest_entry_mut.autotype = original_dest_entry.autotype.clone();
                                dest_entry_mut.times = original_dest_entry.times.clone();
                                dest_entry_mut.custom_data = original_dest_entry.custom_data.clone();
                                dest_entry_mut.icon_id = original_dest_entry.icon_id;
                                dest_entry_mut.custom_icon_uuid = original_dest_entry.custom_icon_uuid;
                                dest_entry_mut.foreground_color = original_dest_entry.foreground_color.clone();
                                dest_entry_mut.background_color = original_dest_entry.background_color.clone();
                                dest_entry_mut.override_url = original_dest_entry.override_url.clone();
                                dest_entry_mut.quality_check = original_dest_entry.quality_check;
                                dest_entry_mut.history = original_dest_entry.history.clone();
                                println!("Keeping destination version for entry {}", uuid);
                            } else {
                                println!("Warning: Could not find entry {} to restore original version", uuid);
                            }
                        } else {
                            println!("Warning: No original destination entry found for {}", uuid);
                        }
                    }
                    "prefer-source" => {
                        // Replace destination entry with source entry
                        if let Some(dest_entry_mut) = find_entry_by_uuid_mut(&mut destination_db.root, &uuid) {
                            add_entry_to_history(dest_entry_mut, &dest_entry, "Destination entry replaced");
                            dest_entry_mut.fields = source_entry.fields.clone();
                            dest_entry_mut.tags = source_entry.tags.clone();
                            // Keep the same UUID and other metadata
                            println!("Replaced destination entry {} with source version", uuid);
                        }
                    }
                    "keep-both" => {
                        // For keep-both, find and remove the current entry from root,
                        // add the original destination entry, and add the source entry as a new entry
                        if let Some(original_dest_entry) = original_destination_entries.get(uuid) {
                            // Find the index of the current entry in root children
                            let mut entry_index = None;
                            for (index, node) in destination_db.root.children.iter().enumerate() {
                                if let keepass::db::Node::Entry(e) = node {
                                    if e.uuid.to_string() == *uuid {
                                        entry_index = Some(index);
                                        break;
                                    }
                                }
                            }
                            
                            if let Some(index) = entry_index {
                                // Remove the current entry
                                destination_db.root.children.remove(index);
                                
                                // Add the original destination entry
                                destination_db.root.children.push(keepass::db::Node::Entry(original_dest_entry.clone()));
                                
                                // Add the source entry as a new entry
                                let mut cloned_entry = source_entry.clone();
                                cloned_entry.uuid = Uuid::new_v4();
                                destination_db.root.children.push(keepass::db::Node::Entry(cloned_entry));
                                
                                println!("Replaced entry {} with original and added cloned source", uuid);
                            } else {
                                // Fallback: just add the source entry
                                let mut cloned_entry = source_entry.clone();
                                cloned_entry.uuid = Uuid::new_v4();
                                destination_db.root.children.push(keepass::db::Node::Entry(cloned_entry));
                                println!("Added cloned source entry for {} with new UUID", uuid);
                            }
                        } else {
                            // Fallback: just add the source entry
                            let mut cloned_entry = source_entry.clone();
                            cloned_entry.uuid = Uuid::new_v4();
                            destination_db.root.children.push(keepass::db::Node::Entry(cloned_entry));
                            println!("Added cloned source entry for {} with new UUID", uuid);
                        }
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

    if args.verbose > 0 {
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

    if args.interactive && !still_conflicting.is_empty() {
        println!("\nInteractive mode: {} entries have conflicts.", still_conflicting.len());
        
        for uuid in &still_conflicting {
            println!("\n--- Entry {} ---", uuid);
            let dest_entry = find_entry_by_uuid(&destination_db.root, uuid);
            let source_entry = find_entry_by_uuid(&source_db.root, uuid);
            
            if let (Some(de), Some(se)) = (dest_entry, source_entry) {
                compare_entries(de, se, "destination", "source");
                
                // Check for timestamp-based resolution
                let timestamp_suggestion = if !args.ignore_threshold {
                    resolve_conflict_by_timestamp_entries(de, se, threshold_seconds)
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
                cleanup_temp_file();
                return Ok(std::process::ExitCode::SUCCESS);
            }
        } else {
            println!("\nConflict resolution complete. Saving database (--yes flag set).");
        }
    } else if auto_resolved_count > 0 && !merge_result.warnings.is_empty() {
        // Automatic timestamp resolution - warnings are informational, don't block saving
        println!("\nAll conflicts were automatically resolved by timestamp comparison.");
        println!("Saving database with resolved conflicts.");
    } else if !args.force && !merge_result.warnings.is_empty() {
        println!("Warnings were generated by the merge operation. Not saving the database.");
        // Clean up temp file
        cleanup_temp_file();
        return Ok(std::process::ExitCode::FAILURE);
    }

    if merge_result.events.len() == 0 {
        // Clean up any leftover temp files
        cleanup_temp_file();
        println!("Nothing to merge.");
        return Ok(std::process::ExitCode::SUCCESS);
    }

    for event in merge_result.events {
        println!("{} {:?}", event.node_uuid, event.event_type);
    }
    if args.dry_run {
        println!("Running in dry-run mode. Not saving the database.");
        // Clean up temp file
        cleanup_temp_file();
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
        cleanup_temp_file();
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
            // Clear temp path since the temp file was successfully renamed
            cleanup_temp_file();
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

fn find_group_by_uuid<'a>(group: &'a Group, uuid: Uuid) -> Option<&'a Group> {
    if group.uuid == uuid {
        return Some(group);
    }
    for node in &group.children {
        if let Node::Group(g) = node {
            if let Some(found) = find_group_by_uuid(g, uuid) {
                return Some(found);
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
    let time1 = get_modification_timestamp(entry1);
    let time2 = get_modification_timestamp(entry2);
    
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

    // Show history differences
    let merge_history1 = entry1.fields.get("MergeHistory");
    let merge_history2 = entry2.fields.get("MergeHistory");
    let history_count1 = entry1.history.as_ref().map(|h| h.get_entries().len()).unwrap_or(0);
    let history_count2 = entry2.history.as_ref().map(|h| h.get_entries().len()).unwrap_or(0);
    
    let history_differs = merge_history1 != merge_history2 || history_count1 != history_count2;
    
    if history_differs {
        println!("  History differs:");
        if merge_history1 != merge_history2 {
            println!("    MergeHistory {}: {:?}", label1, merge_history1);
            println!("    MergeHistory {}: {:?}", label2, merge_history2);
        }
        println!("    KeePass history entries: {} has {}, {} has {}", label1, history_count1, label2, history_count2);
    }
    
    // Always show history timestamps when verbose
    if let Some(history1) = &entry1.history {
        let mut times1: Vec<(std::time::SystemTime, String)> = history1.get_entries().iter()
            .filter_map(|e| parse_modified_timestamp(e).map(|t| (t, format_timestamp(t))))
            .collect();
        times1.sort_by_key(|(time, _)| *time);
        let sorted_times1: Vec<String> = times1.into_iter().map(|(_, formatted)| formatted).collect();
        println!("    History timestamps {}: [{}]", label1, sorted_times1.join(", "));
    }
    if let Some(history2) = &entry2.history {
        let mut times2: Vec<(std::time::SystemTime, String)> = history2.get_entries().iter()
            .filter_map(|e| parse_modified_timestamp(e).map(|t| (t, format_timestamp(t))))
            .collect();
        times2.sort_by_key(|(time, _)| *time);
        let sorted_times2: Vec<String> = times2.into_iter().map(|(_, formatted)| formatted).collect();
        println!("    History timestamps {}: [{}]", label2, sorted_times2.join(", "));
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
    use std::io::{self, Write, BufRead};
    
    loop {
        print!("Enter your choice (1-{}): ", max_choice);
        io::stdout().flush().unwrap();
        
        let mut input = String::new();
        
        // Try to read from /dev/tty if available (for interactive input even when stdin is piped)
        let read_result = if atty::is(atty::Stream::Stdin) {
            // Stdin is a TTY, read from stdin
            io::stdin().read_line(&mut input)
        } else {
            // Stdin is piped, try to read from /dev/tty for interactive input
            match std::fs::File::open("/dev/tty") {
                Ok(mut tty) => {
                    let mut reader = io::BufReader::new(&mut tty);
                    reader.read_line(&mut input)
                }
                Err(_) => {
                    // /dev/tty not available, use default
                    println!("Using default choice (3) since interactive input is not available.");
                    return 3;
                }
            }
        };
        
        match read_result {
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

fn create_temp_db_copy(temp_path: &str, original_path: &str) -> Result<String, std::io::Error> {
    // Read the original file
    let mut original_file = File::open(original_path)?;
    let mut buffer = Vec::new();
    original_file.read_to_end(&mut buffer)?;
    
    // Write to temporary file
    let mut temp_file = File::create(&temp_path)?;
    temp_file.write_all(&buffer)?;
    temp_file.flush()?;
    
    Ok(temp_path.to_string())
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

fn add_entry_to_history(winning_entry: &mut Entry, losing_entry: &Entry, reason: &str) {
    let history_field = winning_entry.fields.entry("MergeHistory".to_string()).or_insert_with(|| keepass::db::Value::Unprotected(String::new()));
    if let keepass::db::Value::Unprotected(ref mut hist_str) = history_field {
        if !hist_str.is_empty() {
            hist_str.push('\n');
        }
        hist_str.push_str(&format!("{} at {}: Title={:?}, UserName={:?}",
            reason,
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
            losing_entry.fields.get("Title"),
            losing_entry.fields.get("UserName")));
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

fn collect_original_timestamps(
    dest_root: &keepass::db::Group,
    source_root: &keepass::db::Group,
    timestamps: &mut std::collections::HashMap<String, (Option<std::time::SystemTime>, Option<std::time::SystemTime>)>,
) {
    fn collect_from_group(
        group: &keepass::db::Group,
        timestamps: &mut std::collections::HashMap<String, (Option<std::time::SystemTime>, Option<std::time::SystemTime>)>,
        is_destination: bool,
    ) {
        for node in &group.children {
            match node {
                keepass::db::Node::Entry(e) => {
                    let uuid = e.uuid.to_string();
                    let time = get_modification_timestamp(e);
                    let entry = timestamps.entry(uuid).or_insert((None, None));
                    if is_destination {
                        entry.0 = time;
                    } else {
                        entry.1 = time;
                    }
                }
                keepass::db::Node::Group(g) => {
                    collect_from_group(g, timestamps, is_destination);
                }
            }
        }
    }
    
    collect_from_group(dest_root, timestamps, true);
    collect_from_group(source_root, timestamps, false);
}

fn collect_original_entries(
    dest_root: &keepass::db::Group,
    _source_root: &keepass::db::Group,
    original_entries: &mut std::collections::HashMap<String, Entry>,
) {
    fn collect_from_group(
        group: &keepass::db::Group,
        original_entries: &mut std::collections::HashMap<String, Entry>,
    ) {
        for node in &group.children {
            match node {
                keepass::db::Node::Entry(e) => {
                    original_entries.insert(e.uuid.to_string(), e.clone());
                }
                keepass::db::Node::Group(g) => {
                    collect_from_group(g, original_entries);
                }
            }
        }
    }
    
    collect_from_group(dest_root, original_entries);
}

fn resolve_conflict_by_timestamp_entries<'a>(dest_entry: &'a Entry, source_entry: &'a Entry, threshold_seconds: u64) -> Option<&'static str> {
    let dest_time = get_modification_timestamp(dest_entry);
    let source_time = get_modification_timestamp(source_entry);
    resolve_conflict_by_timestamp(dest_time, source_time, threshold_seconds)
}

fn resolve_conflict_by_timestamp(dest_time: Option<std::time::SystemTime>, source_time: Option<std::time::SystemTime>, threshold_seconds: u64) -> Option<&'static str> {
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

fn get_modification_timestamp(entry: &Entry) -> Option<std::time::SystemTime> {
    let current_time = parse_modified_timestamp(entry)?;
    log::debug!("Analyzing entry {} for modification timestamp:", entry.uuid);
    log::debug!("  Current LastModificationTime: {}", format_timestamp(current_time));

    let history = entry.history.as_ref()?;
    let history_entries = history.get_entries();
    if history_entries.is_empty() {
        log::debug!("  No history entries, using current time");
        return Some(current_time);
    }

    // Get the latest history entry (most recent)
    let latest_history = history_entries.iter().max_by_key(|e| parse_modified_timestamp(e))?;
    let history_time = parse_modified_timestamp(latest_history)?;
    log::debug!("  Latest history LastModificationTime: {}", format_timestamp(history_time));

    // Compare key fields
    let current_title = entry.fields.get("Title");
    let current_username = entry.fields.get("UserName");
    let current_url = entry.fields.get("URL");
    let current_notes = entry.fields.get("Notes");
    let current_password = entry.fields.get("Password");

    let history_title = latest_history.fields.get("Title");
    let history_username = latest_history.fields.get("UserName");
    let history_url = latest_history.fields.get("URL");
    let history_notes = latest_history.fields.get("Notes");
    let history_password = latest_history.fields.get("Password");

    let fields_match = current_title == history_title &&
                      current_username == history_username &&
                      current_url == history_url &&
                      current_notes == history_notes &&
                      current_password == history_password;

    log::debug!("  Field comparison:");
    log::debug!("    Title: current={:?}, history={:?} ({})", current_title, history_title, current_title == history_title);
    log::debug!("    UserName: current={:?}, history={:?} ({})", current_username, history_username, current_username == history_username);
    log::debug!("    URL: current={:?}, history={:?} ({})", current_url, history_url, current_url == history_url);
    log::debug!("    Notes: current={:?}, history={:?} ({})", current_notes, history_notes, current_notes == history_notes);
    log::debug!("    Password: current={:?}, history={:?} ({})", current_password, history_password, current_password == history_password);
    log::debug!("  All fields match: {}", fields_match);

    if fields_match && history_time > current_time {
        log::debug!("  History has same fields but newer timestamp - using history time as correct modification time");
        Some(history_time)
    } else {
        log::debug!("  Using current LastModificationTime as modification time");
        Some(current_time)
    }
}

fn count_entries(group: &keepass::db::Group) -> usize {
    let mut count = 0;
    for node in &group.children {
        match node {
            keepass::db::Node::Entry(_) => count += 1,
            keepass::db::Node::Group(g) => count += count_entries(g),
        }
    }
    count
}

fn fix_diverged_groups(source_db: &mut keepass::Database, dest_db: &keepass::Database) {
    use keepass::db::{Group, Node};
    use std::collections::HashMap;
    
    // Collect all groups from destination by UUID with their timestamps
    let mut dest_groups = HashMap::new();
    fn collect_groups(group: &Group, groups: &mut HashMap<Uuid, chrono::NaiveDateTime>) {
        if let Some(time) = group.times.get_last_modification() {
            groups.insert(group.uuid, *time);
        }
        for node in &group.children {
            if let Node::Group(child) = node {
                collect_groups(child, groups);
            }
        }
    }
    collect_groups(&dest_db.root, &mut dest_groups);
    
    // Fix source groups that have matching UUID and same timestamp but diverged
    fn fix_source_groups(source_group: &mut Group, dest_groups: &HashMap<Uuid, chrono::NaiveDateTime>, dest_db: &keepass::Database) {
        if let Some(dest_time) = dest_groups.get(&source_group.uuid) {
            let source_time_opt = source_group.times.get_last_modification();
            if let Some(source_time_ref) = source_time_opt {
                let source_time = *source_time_ref;
                if source_time == *dest_time {
                    // Find the corresponding dest group to check divergence
                    if let Some(dest_group) = find_group_by_uuid(&dest_db.root, source_group.uuid) {
                        // Check if groups diverged by comparing relevant fields
                        let groups_diverged = source_group.name != dest_group.name ||
                            source_group.notes != dest_group.notes ||
                            source_group.icon_id != dest_group.icon_id ||
                            source_group.custom_icon_uuid != dest_group.custom_icon_uuid ||
                            source_group.custom_data != dest_group.custom_data ||
                            source_group.is_expanded != dest_group.is_expanded ||
                            source_group.default_autotype_sequence != dest_group.default_autotype_sequence ||
                            source_group.enable_autotype != dest_group.enable_autotype ||
                            source_group.enable_searching != dest_group.enable_searching ||
                            source_group.last_top_visible_entry != dest_group.last_top_visible_entry;
                        
                        if groups_diverged {
                            // Make source timestamp newer by 1 second
                            let new_time = source_time + chrono::Duration::seconds(1);
                            source_group.times.set_last_modification(new_time);
                            println!("Adjusted timestamp for group {} from {} to {}", 
                                source_group.uuid, source_time, new_time);
                        }
                    }
                }
            }
        }
        
        // Recursively fix child groups
        for node in &mut source_group.children {
            if let Node::Group(child) = node {
                fix_source_groups(child, dest_groups, dest_db);
            }
        }
    }
    
    fix_source_groups(&mut source_db.root, &dest_groups, dest_db);
}

fn main() -> Result<std::process::ExitCode> {
    let mut args = KeepassMerge::parse();

    // Clone the destination path for the signal handler
    let destination_db_for_cleanup = args.destination_db.clone();

    // Initialize logging
    let mut builder = env_logger::Builder::from_default_env();
    if args.verbose >= 2 {
        builder.filter_level(log::LevelFilter::Debug);
    } else {
        builder.filter_level(log::LevelFilter::Info);
    }
    builder.init();

    // Set up signal handler for graceful cleanup
    let destination_db_for_cleanup_clone = destination_db_for_cleanup.clone();
    ctrlc::set_handler(move || {
        // Clean up any temp files that match the pattern
        let destination_path = std::path::Path::new(&destination_db_for_cleanup_clone);
        if let Ok(entries) = std::fs::read_dir(destination_path.parent().unwrap_or(std::path::Path::new("."))) {
            for entry in entries {
                if let Ok(entry) = entry {
                    if let Some(file_name) = entry.file_name().to_str() {
                        if file_name.starts_with(".tmpkdbx.") && file_name.contains(&destination_path.file_name().unwrap().to_string_lossy().to_string()) {
                            let _ = std::fs::remove_file(entry.path());
                            eprintln!("\nTemporary file {} cleaned up.", entry.path().display());
                        }
                    }
                }
            }
        }
        std::process::exit(130); // 130 is the standard exit code for SIGINT
    }).expect("Error setting Ctrl+C handler");

    // Check if we have at least one source
    if args.source_db.is_empty() {
        eprintln!("Error: At least one source database must be specified");
        return Ok(std::process::ExitCode::FAILURE);
    }

    // If using same credentials and no password provided, prompt once for all databases
    if args.same_credentials && args.password.is_none() && !args.no_password {
        let password = rpassword::prompt_password("Password for the databases: ")
            .expect("Could not read password from TTY");
        args.password = Some(password);
    }

    // If password is "-", read from stdin
    if let Some(pwd) = &args.password {
        if pwd == "-" {
            let password = resolve_password(pwd)
                .expect("Could not read password from stdin");
            args.password = Some(password);
        }
    }

    // If source_password is "-", read from stdin
    if let Some(pwd) = &args.source_password {
        if pwd == "-" {
            let password = resolve_password(pwd)
                .expect("Could not read password from stdin");
            args.source_password = Some(password);
        }
    }

    // If not using same credentials and no destination password provided, prompt for destination
    if !args.same_credentials && args.password.is_none() && !args.no_password {
        let password = rpassword::prompt_password("Password for the destination database: ")
            .expect("Could not read password from TTY");
        args.password = Some(password);
    }

    // Iterate through all source databases
    let source_paths: Vec<String> = args.source_db.clone();
    let mut any_merge_failed = false;
    for (index, source_path) in source_paths.iter().enumerate() {
        println!("Merging source database {} of {}: {}", index + 1, source_paths.len(), source_path);

        let result = merge_single_source(&mut args, source_path)?;
        
        // If this is not the last source and we had an error, we might want to continue or stop
        // For now, let's continue with other sources even if one fails
        if result != std::process::ExitCode::SUCCESS {
            eprintln!("Warning: Failed to merge source database: {}", source_path);
            any_merge_failed = true;
        }
    }

    println!("All source databases have been processed.");
    if any_merge_failed {
        Ok(std::process::ExitCode::FAILURE)
    } else {
        Ok(std::process::ExitCode::SUCCESS)
    }
}
