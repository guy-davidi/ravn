#!/bin/bash

# RAVN Version Management Script
# Handles version calculation, magic number increment, and version file generation

set -e

VERSION_FILE=".last_version"
VERSION_HEADER="src/version.h"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[VERSION]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to get current date in YYYYMMDD format
get_current_date() {
    date +%Y%m%d
}

# Function to check if there are changes since last version
has_changes() {
    local last_version="$1"
    local last_date=$(echo "$last_version" | cut -d'.' -f1)
    local current_date=$(get_current_date)
    
    if [ "$last_date" = "$current_date" ]; then
        # Same day, check git changes
        if [ -d ".git" ]; then
            # Check if there are uncommitted changes
            if ! git diff --quiet || ! git diff --cached --quiet; then
                return 0  # Has changes
            fi
            
            # Check if there are commits since last version
            local last_commit=$(git log -1 --format="%H" --since="$last_date" 2>/dev/null || echo "")
            if [ -n "$last_commit" ]; then
                return 0  # Has changes
            fi
        fi
        return 1  # No changes
    else
        # Different day, always increment
        return 0  # Has changes
    fi
}

# Function to calculate new version
calculate_version() {
    local current_date=$(get_current_date)
    local new_magic=1
    
    if [ -f "$VERSION_FILE" ]; then
        local last_version=$(cat "$VERSION_FILE")
        local last_date=$(echo "$last_version" | cut -d'.' -f1)
        local last_magic=$(echo "$last_version" | cut -d'.' -f2)
        
        if [ "$last_date" = "$current_date" ]; then
            # Same day, increment magic number
            new_magic=$((last_magic + 1))
        else
            # New day, reset magic to 1
            new_magic=1
        fi
    fi
    
    echo "${current_date}.${new_magic}"
}

# Function to generate version header
generate_version_header() {
    local version="$1"
    local build_date=$(date -u +'%Y-%m-%d')
    local build_time=$(date -u +'%H:%M:%S')
    local commit_sha=""
    
    # Get commit SHA if in git repository
    if [ -d ".git" ]; then
        commit_sha=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    else
        commit_sha="unknown"
    fi
    
    # Parse version components
    local date_part=$(echo "$version" | cut -d'.' -f1)
    local magic_part=$(echo "$version" | cut -d'.' -f2)
    
    local year=$(echo "$date_part" | cut -c1-4)
    local month=$(echo "$date_part" | cut -c5-6)
    local day=$(echo "$date_part" | cut -c7-8)
    
    # Remove leading zeros to avoid octal constant issues
    local year_num=$((10#$year))
    local month_num=$((10#$month))
    local day_num=$((10#$day))
    local magic_num=$((10#$magic_part))
    
    # Create version header
    cat > "$VERSION_HEADER" << EOF
#ifndef RAVN_VERSION_H
#define RAVN_VERSION_H

// Auto-generated version information
// Generated on: $(date -u +'%Y-%m-%d %H:%M:%S UTC')

#define RAVN_VERSION_MAJOR $year_num
#define RAVN_VERSION_MINOR $month_num
#define RAVN_VERSION_PATCH $day_num
#define RAVN_VERSION_MAGIC $magic_num
#define RAVN_VERSION_STRING "$version"
#define RAVN_BUILD_DATE "$build_date"
#define RAVN_BUILD_TIME "$build_time"
#define RAVN_COMMIT_SHA "$commit_sha"

// Version format: YYYYMMDD.MAGIC
// - YYYYMMDD: Date when version was created
// - MAGIC: Incremental number for same-day builds

#endif // RAVN_VERSION_H
EOF
}

# Function to show current version
show_version() {
    if [ -f "$VERSION_FILE" ]; then
        local version=$(cat "$VERSION_FILE")
        print_status "Current version: $version"
        
        if [ -f "$VERSION_HEADER" ]; then
            echo ""
            print_status "Version header contents:"
            cat "$VERSION_HEADER"
        fi
    else
        print_warning "No version file found. Run 'version.sh update' to create initial version."
    fi
}

# Function to update version
update_version() {
    local force_update="$1"
    local current_date=$(get_current_date)
    
    print_status "Updating version..."
    
    if [ -f "$VERSION_FILE" ]; then
        local last_version=$(cat "$VERSION_FILE")
        print_status "Last version: $last_version"
        
        if [ "$force_update" != "force" ]; then
            if ! has_changes "$last_version"; then
                print_warning "No changes detected since last version. Use 'force' to update anyway."
                return 0
            fi
        fi
    fi
    
    local new_version=$(calculate_version)
    echo "$new_version" > "$VERSION_FILE"
    
    generate_version_header "$new_version"
    
    print_success "Version updated to: $new_version"
    print_status "Version file: $VERSION_FILE"
    print_status "Header file: $VERSION_HEADER"
}

# Function to reset version
reset_version() {
    local new_version=$(get_current_date).1
    echo "$new_version" > "$VERSION_FILE"
    generate_version_header "$new_version"
    print_success "Version reset to: $new_version"
}

# Function to show help
show_help() {
    echo "RAVN Version Management Script"
    echo ""
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  show     - Show current version information"
    echo "  update   - Update version (only if changes detected)"
    echo "  force    - Force version update (ignore change detection)"
    echo "  reset    - Reset version to current date with magic 1"
    echo "  help     - Show this help message"
    echo ""
    echo "Version Format: YYYYMMDD.MAGIC"
    echo "  - YYYYMMDD: Date when version was created"
    echo "  - MAGIC: Incremental number for same-day builds"
    echo ""
    echo "Examples:"
    echo "  $0 show          # Show current version"
    echo "  $0 update        # Update if changes detected"
    echo "  $0 force         # Force update regardless of changes"
    echo "  $0 reset         # Reset to current date.1"
}

# Main script logic
main() {
    cd "$PROJECT_ROOT"
    
    case "${1:-show}" in
        "show")
            show_version
            ;;
        "update")
            update_version
            ;;
        "force")
            update_version "force"
            ;;
        "reset")
            reset_version
            ;;
        "help"|"-h"|"--help")
            show_help
            ;;
        *)
            print_error "Unknown command: $1"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
