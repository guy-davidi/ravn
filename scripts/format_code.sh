#!/bin/bash
#
# RAVN Code Formatting Script
# 
# This script applies Linux kernel style formatting to the RAVN codebase
# using clang-format. It ensures consistent code style across all C/C++ files.
#
# Usage:
#   ./scripts/format_code.sh [--check] [--fix] [--help]
#
# Options:
#   --check    Check if code is properly formatted (exit 1 if not)
#   --fix      Apply formatting to all files
#   --help     Show this help message
#
# Examples:
#   ./scripts/format_code.sh --check    # Check formatting
#   ./scripts/format_code.sh --fix      # Fix formatting
#

# set -e  # Removed to allow proper error handling in functions

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Default options
CHECK_ONLY=false
FIX_FORMATTING=false
SHOW_HELP=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --check)
            CHECK_ONLY=true
            shift
            ;;
        --fix)
            FIX_FORMATTING=true
            shift
            ;;
        --help)
            SHOW_HELP=true
            shift
            ;;
        *)
            echo -e "${RED}Error: Unknown option $1${NC}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Show help
if [ "$SHOW_HELP" = true ]; then
    echo "RAVN Code Formatting Script"
    echo ""
    echo "This script applies Linux kernel style formatting to the RAVN codebase"
    echo "using clang-format. It ensures consistent code style across all C/C++ files."
    echo ""
    echo "Usage:"
    echo "  $0 [--check] [--fix] [--help]"
    echo ""
    echo "Options:"
    echo "  --check    Check if code is properly formatted (exit 1 if not)"
    echo "  --fix      Apply formatting to all files"
    echo "  --help     Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --check    # Check formatting"
    echo "  $0 --fix      # Fix formatting"
    exit 0
fi

# Check if clang-format is available
if ! command -v clang-format &> /dev/null; then
    echo -e "${RED}Error: clang-format is not installed${NC}"
    echo ""
    echo "Please install clang-format:"
    echo "  Ubuntu/Debian: sudo apt-get install clang-format"
    echo "  CentOS/RHEL:   sudo yum install clang-tools-extra"
    echo "  Fedora:        sudo dnf install clang-tools-extra"
    echo "  Arch Linux:    sudo pacman -S clang"
    echo ""
    exit 1
fi

# Check clang-format version
CLANG_FORMAT_VERSION=$(clang-format --version | grep -o '[0-9]\+\.[0-9]\+' | head -1)
echo -e "${BLUE}Using clang-format version: $CLANG_FORMAT_VERSION${NC}"

# Find all C/C++ files
echo -e "${BLUE}Scanning for C/C++ files...${NC}"
FILES=$(find "$PROJECT_ROOT" -type f \( -name "*.c" -o -name "*.h" -o -name "*.cpp" -o -name "*.hpp" -o -name "*.cc" -o -name "*.cxx" \) \
    ! -path "*/build/*" \
    ! -path "*/artifacts/*" \
    ! -path "*/.git/*" \
    ! -path "*/node_modules/*" \
    ! -path "*/venv/*" \
    ! -path "*/env/*")

if [ -z "$FILES" ]; then
    echo -e "${YELLOW}Warning: No C/C++ files found${NC}"
    exit 0
fi

FILE_COUNT=$(echo "$FILES" | wc -l)
echo -e "${BLUE}Found $FILE_COUNT C/C++ files${NC}"

# Check if .clang-format exists
if [ ! -f "$PROJECT_ROOT/.clang-format" ]; then
    echo -e "${RED}Error: .clang-format file not found in project root${NC}"
    echo "Please ensure .clang-format exists in $PROJECT_ROOT"
    exit 1
fi

# Function to check formatting
check_formatting() {
    local files_to_check="$1"
    local unformatted_files=()
    
    echo -e "${BLUE}Checking code formatting...${NC}"
    
    for file in $files_to_check; do
        if ! clang-format --dry-run --Werror "$file" > /dev/null 2>&1; then
            unformatted_files+=("$file")
        fi
    done
    
    if [ ${#unformatted_files[@]} -eq 0 ]; then
        echo -e "${GREEN}✓ All files are properly formatted${NC}"
        return 0
    else
        echo -e "${RED}✗ Found ${#unformatted_files[@]} files with formatting issues:${NC}"
        for file in "${unformatted_files[@]}"; do
            echo -e "${RED}  - $file${NC}"
        done
        return 1
    fi
}

# Function to fix formatting
fix_formatting() {
    local files_to_fix="$1"
    local fixed_count=0
    
    echo -e "${BLUE}Applying code formatting...${NC}"
    
    for file in $files_to_fix; do
        echo -e "${YELLOW}Formatting: $file${NC}"
        if clang-format -i "$file"; then
            ((fixed_count++))
        else
            echo -e "${RED}Error formatting: $file${NC}"
        fi
    done
    
    echo -e "${GREEN}✓ Formatted $fixed_count files${NC}"
}

# Main execution
if [ "$CHECK_ONLY" = true ]; then
    check_formatting "$FILES"
    exit $?
elif [ "$FIX_FORMATTING" = true ]; then
    fix_formatting "$FILES"
    echo -e "${GREEN}Code formatting complete!${NC}"
    exit 0
else
    echo -e "${YELLOW}No action specified. Use --check or --fix${NC}"
    echo "Use --help for more information"
    exit 1
fi
