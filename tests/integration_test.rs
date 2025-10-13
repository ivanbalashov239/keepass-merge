use std::process::Command;

/// Test basic functionality of the keepass-merge tool
#[test]
fn test_help_output() {
    let output = Command::new("cargo")
        .args(&["run", "--bin", "keepass-merge", "--", "--help"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("CLI tool to merge KDBX"));
    assert!(stdout.contains("Usage:"));
}

/// Test threshold parsing functionality
#[test]
fn test_threshold_parsing() {
    // Test the parse_threshold function indirectly through the CLI
    let output = Command::new("cargo")
        .args(&["run", "--bin", "keepass-merge", "--", "--threshold", "1h", "--dry-run", "dummy1.kdbx", "dummy2.kdbx"])
        .output()
        .expect("Failed to execute command");

    // Should fail because files don't exist, but should parse threshold successfully
    // The exact behavior depends on how the CLI handles missing files
    let stderr = String::from_utf8_lossy(&output.stderr);
    // We expect it to fail on file operations, not threshold parsing
    assert!(!stderr.contains("Invalid threshold format"));
}

/// Test that the tool requires proper arguments
#[test]
fn test_requires_arguments() {
    let output = Command::new("cargo")
        .args(&["run", "--bin", "keepass-merge"])
        .output()
        .expect("Failed to execute command");

    // Should show help or error about missing arguments
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Usage") || stderr.contains("error"));
}

/// Test verbose flag parsing
#[test]
fn test_verbose_flags() {
    let output = Command::new("cargo")
        .args(&["run", "--bin", "keepass-merge", "--", "-v", "--dry-run", "dummy1.kdbx", "dummy2.kdbx"])
        .output()
        .expect("Failed to execute command");

    // Should handle verbose flag without crashing
    // The exact output depends on file existence, but should not crash on flag parsing
    assert!(output.status.code().is_some()); // Should exit with some code
}

/// Test debug logging with -vv flag
#[test]
fn test_debug_logging() {
    let output = Command::new("cargo")
        .args(&["run", "--bin", "keepass-merge", "--", "-vv", "--dry-run", "dummy1.kdbx", "dummy2.kdbx"])
        .output()
        .expect("Failed to execute command");

    // Should handle debug flag without crashing
    assert!(output.status.code().is_some());
}

/// Test that invalid threshold formats are rejected
#[test]
fn test_invalid_threshold() {
    let output = Command::new("cargo")
        .args(&["run", "--bin", "keepass-merge", "--", "--threshold", "invalid", "--dry-run", "dummy1.kdbx", "dummy2.kdbx"])
        .output()
        .expect("Failed to execute command");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Invalid threshold format"));
}

/// Test merging real KeePass databases with conflicts
#[test]
fn test_merge_with_conflicts() {
    let output = Command::new("cargo")
        .args(&["run", "--bin", "keepass-merge", "--", "--dry-run", "--password", "test", "--password-from", "test",
                "tests/resources/Passwords.kdbx", "tests/resources/Passwords.sync-conflict-20241216-230652-NCVDYTT.kdbx"])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should successfully open both databases
    assert!(stdout.contains("Opening the destination database"));
    assert!(stdout.contains("Opening the source database"));

    // Should detect conflicts
    assert!(stdout.contains("Conflicts detected during merge"));

    // Should perform timestamp-based resolution
    assert!(stdout.contains("Starting timestamp-based conflict resolution"));

    // Should show diff information
    assert!(stdout.contains("Diff before resolution"));
    assert!(stdout.contains("Diff after resolution"));

    // Should resolve conflicts automatically
    assert!(stdout.contains("All") && stdout.contains("conflicts were automatically resolved"));

    // Should generate warnings and not save due to dry-run
    assert!(stderr.contains("Warnings were generated") || stdout.contains("Warnings were generated"));
    assert!(stderr.contains("Not saving the database") || stdout.contains("Not saving the database"));

    // Ensure temp files are cleaned up
    assert!(!std::path::Path::new("tests/resources/.tmpkdbx.Passwords.kdbx").exists());
    assert!(!std::path::Path::new("tests/resources/.tmpkdbx.Passwords.sync-conflict-20241216-230652-NCVDYTT.kdbx").exists());
}

/// Test verbose output with real databases
#[test]
fn test_verbose_merge_output() {
    let output = Command::new("cargo")
        .args(&["run", "--bin", "keepass-merge", "--", "-v", "--dry-run", "--password", "test", "--password-from", "test",
                "tests/resources/Passwords.kdbx", "tests/resources/Passwords.sync-conflict-20241216-230652-NCVDYTT.kdbx"])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should show entry counts
    assert!(stdout.contains("entries"));

    // Ensure temp files are cleaned up
    assert!(!std::path::Path::new("tests/resources/.tmpkdbx.Passwords.kdbx").exists());
    assert!(!std::path::Path::new("tests/resources/.tmpkdbx.Passwords.sync-conflict-20241216-230652-NCVDYTT.kdbx").exists());
}

/// Test debug logging with real databases
#[test]
fn test_debug_merge_output() {
    let output = Command::new("cargo")
        .args(&["run", "--bin", "keepass-merge", "--", "-vv", "--dry-run", "--password", "test", "--password-from", "test",
                "tests/resources/Passwords.kdbx", "tests/resources/Passwords.sync-conflict-20241216-230652-NCVDYTT.kdbx"])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should show debug information
    assert!(stdout.contains("Reading original destination database") || stdout.contains("Creating temporary copy"));

    // Ensure temp files are cleaned up
    assert!(!std::path::Path::new("tests/resources/.tmpkdbx.Passwords.kdbx").exists());
    assert!(!std::path::Path::new("tests/resources/.tmpkdbx.Passwords.sync-conflict-20241216-230652-NCVDYTT.kdbx").exists());
}

/// Test that merge operations modify the database and prevent re-conflicts
#[test]
fn test_merge_modifies_database() {
    use std::fs;
    use std::path::Path;

    // Create a temporary copy of the destination database
    let temp_db_path = "tests/resources/temp_test_db.kdbx";
    let original_db_path = "tests/resources/Passwords.kdbx";
    let conflict_db_path = "tests/resources/Passwords.sync-conflict-20241216-230652-NCVDYTT.kdbx";

    // Clean up any existing temp file
    if Path::new(temp_db_path).exists() {
        fs::remove_file(temp_db_path).expect("Failed to remove existing temp file");
    }

    // Copy the original database
    fs::copy(original_db_path, temp_db_path).expect("Failed to create temp copy of database");

    // First merge: should find and resolve conflicts
    let first_output = Command::new("cargo")
        .args(&["run", "--bin", "keepass-merge", "--", "--yes", "--force", "--password", "test", "--password-from", "test",
                temp_db_path, conflict_db_path])
        .output()
        .expect("Failed to execute first merge");

    let first_stdout = String::from_utf8_lossy(&first_output.stdout);
    let first_stderr = String::from_utf8_lossy(&first_output.stderr);

    // Should have found and resolved conflicts
    assert!(first_stdout.contains("Conflicts detected during merge"));
    assert!(first_stdout.contains("conflicts were automatically resolved"));
    assert!(first_output.status.success() || first_stdout.contains("WARNING") || first_stderr.contains("WARNING"));

    // Second merge: should not find conflicts since they were already resolved
    let second_output = Command::new("cargo")
        .args(&["run", "--bin", "keepass-merge", "--", "--dry-run", "--password", "test", "--password-from", "test",
                temp_db_path, conflict_db_path])
        .output()
        .expect("Failed to execute second merge");

    let second_stdout = String::from_utf8_lossy(&second_output.stdout);

    // Should not detect conflicts on the second pass
    assert!(!second_stdout.contains("Conflicts detected during merge"));
    assert!(second_stdout.contains("Opening the destination database"));
    assert!(second_stdout.contains("Opening the source database"));

    // Ensure temp files are cleaned up
    assert!(!std::path::Path::new("tests/resources/.tmpkdbx.temp_test_db.kdbx").exists());
    assert!(!std::path::Path::new("tests/resources/.tmpkdbx.Passwords.sync-conflict-20241216-230652-NCVDYTT.kdbx").exists());

    // Clean up
    if Path::new(temp_db_path).exists() {
        fs::remove_file(temp_db_path).expect("Failed to clean up temp file");
    }
}