#!/bin/bash

# RAVN Release Management Script
# Handles release creation, tagging, and GitHub integration

set -e

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
    echo -e "${BLUE}[RELEASE]${NC} $1"
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

# Function to get current version
get_current_version() {
    if [ -f ".last_version" ]; then
        cat .last_version
    else
        print_error "No version file found. Run 'make version-update' first."
        exit 1
    fi
}

# Function to check if we're in a git repository
check_git_repo() {
    if [ ! -d ".git" ]; then
        print_error "Not in a git repository"
        exit 1
    fi
}

# Function to check if there are uncommitted changes
check_clean_working_tree() {
    if ! git diff --quiet || ! git diff --cached --quiet; then
        print_warning "You have uncommitted changes"
        read -p "Do you want to continue? [y/N]: " confirm
        if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
            print_status "Release cancelled"
            exit 0
        fi
    fi
}

# Function to create a local release
create_local_release() {
    local version="$1"
    local release_notes="$2"
    
    print_status "Creating local release for version $version"
    
    # Create release directory
    local release_dir="releases/v$version"
    mkdir -p "$release_dir"
    
    # Build the project
    print_status "Building project..."
    make clean-ci
    make all
    
    if [ ! -f "artifacts/ravn" ]; then
        print_error "Build failed - binary not found"
        exit 1
    fi
    
    # Copy binary
    cp artifacts/ravn "$release_dir/ravn-$version-linux-x86_64"
    
    # Create checksums
    cd "$release_dir"
    sha256sum ravn-$version-linux-x86_64 > ravn-$version-linux-x86_64.sha256
    md5sum ravn-$version-linux-x86_64 > ravn-$version-linux-x86_64.md5
    
    # Create archive
    tar -czf ravn-$version-linux-x86_64.tar.gz ravn-$version-linux-x86_64
    sha256sum ravn-$version-linux-x86_64.tar.gz > ravn-$version-linux-x86_64.tar.gz.sha256
    
    # Create installation script
    cat > install-ravn-$version.sh << EOF
#!/bin/bash
# RAVN Security Platform Installation Script

set -e

echo "RAVN Security Platform v$version Installation"
echo "=============================================="

# Check if running as root
if [ "\$EUID" -eq 0 ]; then
  echo "Please do not run this script as root"
  exit 1
fi

# Check dependencies
echo "Checking dependencies..."

if ! command -v gcc &> /dev/null; then
  echo "Error: gcc is required but not installed"
  echo "Please install: sudo apt-get install build-essential"
  exit 1
fi

if ! command -v redis-server &> /dev/null; then
  echo "Error: Redis is required but not installed"
  echo "Please install: sudo apt-get install redis-server"
  exit 1
fi

# Install binary
echo "Installing RAVN binary..."
sudo cp ravn-$version-linux-x86_64 /usr/local/bin/ravn
sudo chmod +x /usr/local/bin/ravn

# Verify installation
if /usr/local/bin/ravn --version; then
  echo ""
  echo "Installation successful!"
  echo "RAVN Security Platform v$version is now installed"
  echo ""
  echo "Usage:"
  echo "  sudo ravn daemon    # Start monitoring daemon"
  echo "  ravn cli           # Start CLI dashboard"
  echo "  ravn --version     # Show version information"
  echo "  ravn --help        # Show help"
else
  echo "Error: Installation verification failed"
  exit 1
fi
EOF
    
    chmod +x install-ravn-$version.sh
    
    cd "$PROJECT_ROOT"
    
    print_success "Local release created in $release_dir"
    print_status "Files created:"
    ls -la "$release_dir"
}

# Function to create git tag
create_git_tag() {
    local version="$1"
    local release_notes="$2"
    
    print_status "Creating git tag v$version"
    
    # Check if tag already exists
    if git rev-parse "v$version" >/dev/null 2>&1; then
        print_warning "Tag v$version already exists"
        read -p "Do you want to delete and recreate it? [y/N]: " confirm
        if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
            git tag -d "v$version"
            git push origin ":refs/tags/v$version" 2>/dev/null || true
        else
            print_status "Skipping tag creation"
            return 0
        fi
    fi
    
    # Create tag with release notes
    if [ -n "$release_notes" ]; then
        git tag -a "v$version" -m "$release_notes"
    else
        git tag -a "v$version" -m "Release v$version"
    fi
    
    # Push tag
    git push origin "v$version"
    
    print_success "Git tag v$version created and pushed"
}

# Function to trigger GitHub release
trigger_github_release() {
    local version="$1"
    
    print_status "Triggering GitHub release workflow..."
    
    # Check if gh CLI is available
    if ! command -v gh &> /dev/null; then
        print_warning "GitHub CLI (gh) not found. Please install it to trigger releases automatically."
        print_status "You can manually trigger the release workflow from GitHub Actions"
        return 0
    fi
    
    # Check if authenticated
    if ! gh auth status &> /dev/null; then
        print_warning "Not authenticated with GitHub CLI. Please run 'gh auth login'"
        print_status "You can manually trigger the release workflow from GitHub Actions"
        return 0
    fi
    
    # Trigger workflow
    gh workflow run release.yml --ref "$(git branch --show-current)" || {
        print_warning "Failed to trigger workflow automatically"
        print_status "You can manually trigger the release workflow from GitHub Actions"
    }
}

# Function to show help
show_help() {
    echo "RAVN Release Management Script"
    echo ""
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  local [version] [notes]  - Create local release"
    echo "  tag [version] [notes]    - Create git tag"
    echo "  github [version]         - Trigger GitHub release"
    echo "  full [version] [notes]   - Create local release, tag, and trigger GitHub"
    echo "  list                     - List existing releases"
    echo "  help                     - Show this help message"
    echo ""
    echo "Options:"
    echo "  version                  - Version number (default: current version)"
    echo "  notes                    - Release notes (optional)"
    echo ""
    echo "Examples:"
    echo "  $0 local                 # Create local release with current version"
    echo "  $0 local 20241215.1      # Create local release with specific version"
    echo "  $0 tag                   # Create git tag with current version"
    echo "  $0 full                  # Full release process"
    echo "  $0 list                  # List existing releases"
}

# Function to list releases
list_releases() {
    print_status "Listing releases..."
    
    # List local releases
    if [ -d "releases" ]; then
        echo ""
        echo "Local releases:"
        ls -la releases/ 2>/dev/null || echo "No local releases found"
    fi
    
    # List git tags
    echo ""
    echo "Git tags:"
    git tag -l "v*" | sort -V || echo "No git tags found"
    
    # List GitHub releases (if gh CLI is available)
    if command -v gh &> /dev/null && gh auth status &> /dev/null; then
        echo ""
        echo "GitHub releases:"
        gh release list || echo "No GitHub releases found"
    fi
}

# Main script logic
main() {
    cd "$PROJECT_ROOT"
    
    case "${1:-help}" in
        "local")
            local version="${2:-$(get_current_version)}"
            local notes="$3"
            check_git_repo
            create_local_release "$version" "$notes"
            ;;
        "tag")
            local version="${2:-$(get_current_version)}"
            local notes="$3"
            check_git_repo
            check_clean_working_tree
            create_git_tag "$version" "$notes"
            ;;
        "github")
            local version="${2:-$(get_current_version)}"
            check_git_repo
            trigger_github_release "$version"
            ;;
        "full")
            local version="${2:-$(get_current_version)}"
            local notes="$3"
            check_git_repo
            check_clean_working_tree
            create_local_release "$version" "$notes"
            create_git_tag "$version" "$notes"
            trigger_github_release "$version"
            print_success "Full release process completed for v$version"
            ;;
        "list")
            list_releases
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
