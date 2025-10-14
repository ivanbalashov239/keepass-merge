#!/usr/bin/env bash

shopt -s nullglob

# directory : direcCONFLICT_PATTERN="(.*\.sync-conflict-.*\.kdbx\|.* \\(conflicted copy [^)]+\\)\\.kdbx\|.*_conflict_.*\\.kdbx\|.*-conflict-.*\\.kdbx)"ory where .kdbx fil    conflict_files_for_original=($(find "$DIRECTORY" -wholename "$DIRECTORY/$base_name.sync-conflict-*.kbdx" -type f))onflict_files_for_original=($(find "$DIRECTORY" -wholename "$DIRECTORY/$base_name.sync-conflict-*.kbdx" -type f))re located
# --gui_command : command to launch GUI mode of keepass-merge, if not set use KEEPASS_MERGE_GUI env var

# parse arguments and options
DIRECTORY=""
KEEPASS_MERGE_EXTRAARGS=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --gui_command)
            if [[ -z "$2" || "$2" == --* ]]; then
                echo "Error: --gui_command requires a command argument"
                exit 1
            fi
            KEEPASS_MERGE_GUI="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 <directory> [--gui_command <command>] [--help] [KEEPASS_MERGE_EXTRAARGS] [--pass_file <file>] [--move_on_removal]"
            exit 0
            ;;

        --pass_file)
            KEEPASS_PASSWORD_FILE="$2"
            echo "Using password file: $KEEPASS_PASSWORD_FILE"
            KEEPASS_MERGE_EXTRAARGS="$KEEPASS_MERGE_EXTRAARGS --password - "
            shift 2
            ;;
        --move_on_removal)
            KEEPASS_MOVE_ON_REMOVAL=true
            shift
            ;;
        --*)
            # Unknown option, treat as extra argument for keepass-merge
            KEEPASS_MERGE_EXTRAARGS="$KEEPASS_MERGE_EXTRAARGS $1"
            shift
            ;;
        *)
            if [[ -z "$DIRECTORY" ]]; then
                DIRECTORY="$1"
            else
                KEEPASS_MERGE_EXTRAARGS="$KEEPASS_MERGE_EXTRAARGS $1"
            fi
            shift
            ;;
    esac
done

if [[ -z "$DIRECTORY" ]]; then
    echo "Error: Directory argument is required"
    echo "Usage: $0 <directory> [--gui_command <command>] [--help] [KEEPASS_MERGE_EXTRAARGS]"
    exit 1
fi

# Normalize DIRECTORY to remove trailing slash
DIRECTORY="${DIRECTORY%/}"
#if DIRECTORY is a file, get its directory
if [[ -f "$DIRECTORY" ]]; then
    DIRECTORY="$(dirname "$DIRECTORY")"
fi

CONFLICT_PATTERN="${CONFLICT_PATTERN:-.*\.sync-conflict-.*\.kdbx\|.* \(conflicted copy [^)]+\)\.kdbx\|.*_conflict_.*\.kdbx\|.*-conflict-.*\.kdbx}"

# logic, find all  sync-conflict files in the directory, for each of them determine original file, iterate original files, and for each of them execute keepass-merge with asterisk sync-conflict files
set -e
echo "Directory: $DIRECTORY"

cmd="find \"$DIRECTORY\" -maxdepth 1 -regex \"$CONFLICT_PATTERN\" -type f"
mapfile -t conflict_files < <(eval "$cmd")

# Function to extract original filename from conflict filename
extract_original_filename() {
    local conflict_file="$1"
    local base_name
    base_name=$(basename "$conflict_file")
    
    # Handle different conflict patterns
    if [[ "$base_name" == *".sync-conflict-"* ]]; then
        echo "${conflict_file%.sync-conflict-*}.kdbx"
    elif [[ "$base_name" == *" (conflicted copy "* ]]; then
        echo "${conflict_file% (conflicted copy *}.kdbx"
    elif [[ "$base_name" == *"_conflict_"* ]]; then
        echo "${conflict_file%_conflict_*}.kdbx"
    elif [[ "$base_name" == *"-conflict-"* ]]; then
        echo "${conflict_file%-conflict-*}.kdbx"
    else
        # Fallback
        echo "${conflict_file}"
    fi
}

# map for original files
declare -A original_files_map
for conflict_file in "${conflict_files[@]}"; do
    # Extract the original file name
    original_file=$(extract_original_filename "$conflict_file")
    original_files_map["$original_file"]=1
done
echo "Found ${#original_files_map[@]} unique original files."


# Iterate over original files and merge corresponding conflict files
for original_file in "${!original_files_map[@]}"; do
    # Find all conflict files for this original file
    base_name="$(basename "${original_file%.kdbx}")"
    conflict_files_for_original=()
    for conflict_file in "${conflict_files[@]}"; do
        conflict_original=$(extract_original_filename "$conflict_file")
        conflict_base="$(basename "${conflict_original%.kdbx}")"
        if [[ "$conflict_base" == "$base_name" ]]; then
            conflict_files_for_original+=("$conflict_file")
        fi
    done
    if [ ${#conflict_files_for_original[@]} -gt 0 ]; then # Check if at least one conflict file exists
        echo "Merging ${#conflict_files_for_original[@]} conflicts for $original_file"
        cmd="keepass-merge -s -y $KEEPASS_MERGE_EXTRAARGS $original_file ${conflict_files_for_original[*]}"
        # if root launch with user of original file owner
        user_of_original_file=$(stat -c '%U' "$original_file")
        if [ "$(id -u)" -eq 0 ]; then
            cmd="sudo -u \"$user_of_original_file\" $cmd"
        fi
        if [ -n "$KEEPASS_PASSWORD_FILE" ] && [ -f "$KEEPASS_PASSWORD_FILE" ]; then
            cmd="cat $KEEPASS_PASSWORD_FILE | $cmd"
        fi
        first_conflict_file="${conflict_files_for_original[0]}"
        conflict_dir="$(dirname "$first_conflict_file")/.${base_name}_merged_conflicts"
        make_dir_function() {
            if [ "$(id -u)" -eq 0 ]; then
                sudo -u "$user_of_original_file" mkdir -p "$conflict_dir"
            else
                mkdir -p "$conflict_dir"
            fi
        }
        # Execute keepass-merge with all conflict files in non-interactive mode, if not passes launch interactive
        if [[ "$KEEPASS_MERGE_EXTRAARGS" == *" -d"* ]] || [[ "$KEEPASS_MERGE_EXTRAARGS" == *" --dry-run"* ]]; then
            remove_cmd="echo 'Dry run mode: would remove conflict files: ${conflict_files_for_original[*]}'"
        else
            # Create conflict directory if it doesn't exist
            make_dir_function
            if [ "$KEEPASS_MOVE_ON_REMOVAL" = true ]; then
                            remove_cmd="sudo -u \"$user_of_original_file\" mkdir -p $conflict_dir && sudo -u \"$user_of_original_file\" mv -v ${conflict_files_for_original[*]} $conflict_dir/"
            else
                remove_cmd="rm -v ${conflict_files_for_original[*]}"
            fi
        fi
        if [ "$KEEPASS_MOVE_ON_REMOVAL" = true ]; then
            # Create conflict directory if it doesn't exist
            make_dir_function
            #copy original file to conflict dir before merging
            datetime=$(date +%Y%m%d_%H%M%S)
            new_path="$conflict_dir/$base_name.original_$datetime.kdbx"
            if [ "$(id -u)" -eq 0 ]; then
                sudo -u "$user_of_original_file" cp -v "$original_file" "$new_path"
            else
                cp -v "$original_file" "$new_path"
            fi
        fi
        # Execute keepass-merge
        if ! eval "$cmd"; then
            echo "Non-interactive merge failed for $original_file, launching interactive mode."
            if [ -n "$KEEPASS_MERGE_GUI" ]; then
                echo "Launching GUI mode"
                $KEEPASS_MERGE_GUI "bash -c '$cmd -i'" && eval "$remove_cmd"
            else
                echo "No GUI command specified, launching interactive mode in terminal."
                eval "$cmd -i" && eval "$remove_cmd"
            fi
        else
            echo "Debug: Merge command executed successfully."
            echo "Merge successful, removing conflict files."
            eval "$remove_cmd"
        fi

        # if conflict dir is empty remove it
        if [ -d "$conflict_dir" ] && [ -z "$(ls -A "$conflict_dir")" ]; then
            echo "Conflict directory $conflict_dir is empty, removing it."
            rmdir "$conflict_dir"
        fi
    else
        echo "No conflict files found for $original_file"
    fi
done