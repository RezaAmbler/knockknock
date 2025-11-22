#!/bin/bash
#
# Knock Knock Security Scanner - Setup Script
#
# This script sets up the environment for running the Knock Knock scanner.
# It checks dependencies, installs required tools, and optionally creates a virtual environment.
#
# Usage:
#   ./setup.sh              # Interactive setup
#   ./setup.sh --venv       # Force virtual environment creation
#   ./setup.sh --no-venv    # Skip virtual environment (system-wide install)
#   ./setup.sh --check-only # Only check dependencies, don't install anything
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Track what needs to be done
NEEDS_SYSTEM_TOOLS=false
NEEDS_PYTHON_DEPS=false
USE_VENV=""
CHECK_ONLY=false

# Parse command line arguments
for arg in "$@"; do
    case $arg in
        --venv)
            USE_VENV="yes"
            shift
            ;;
        --no-venv)
            USE_VENV="no"
            shift
            ;;
        --check-only)
            CHECK_ONLY=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --venv        Force virtual environment creation"
            echo "  --no-venv     Skip virtual environment (install system-wide)"
            echo "  --check-only  Only check dependencies, don't install"
            echo "  --help        Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $arg${NC}"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}   Knock Knock Security Scanner - Setup${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check Python version
check_python_version() {
    if ! command_exists python3; then
        echo -e "${RED}✗ Python 3 not found${NC}"
        return 1
    fi

    local python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    local major=$(echo $python_version | cut -d. -f1)
    local minor=$(echo $python_version | cut -d. -f2)

    if [ "$major" -ge 3 ] && [ "$minor" -ge 8 ]; then
        echo -e "${GREEN}✓ Python $python_version (>= 3.8 required)${NC}"
        return 0
    else
        echo -e "${RED}✗ Python $python_version found, but 3.8+ required${NC}"
        return 1
    fi
}

# Function to check system tools
check_system_tools() {
    echo -e "\n${BLUE}Checking required system tools...${NC}"

    local all_found=true
    local tools=("masscan" "nmap" "ssh-audit")

    for tool in "${tools[@]}"; do
        if command_exists "$tool"; then
            local version=$($tool --version 2>&1 | head -n1 || echo "unknown")
            echo -e "${GREEN}✓ $tool found${NC} - $version"
        else
            echo -e "${RED}✗ $tool not found${NC}"
            all_found=false
            NEEDS_SYSTEM_TOOLS=true
        fi
    done

    # Check optional tool: nuclei (for vulnerability scanning)
    echo -e "\n${BLUE}Checking optional tools...${NC}"
    if command_exists nuclei; then
        local nuclei_version=$(nuclei -version 2>&1 | head -n1 || echo "unknown")
        echo -e "${GREEN}✓ nuclei found${NC} - $nuclei_version"
    else
        echo -e "${YELLOW}! nuclei not found (optional - for vulnerability scanning)${NC}"
        echo -e "  To install nuclei, visit: https://github.com/projectdiscovery/nuclei"
        echo -e "  Or run: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    fi

    if [ "$all_found" = false ]; then
        return 1
    fi
    return 0
}

# Function to check Python dependencies
check_python_deps() {
    echo -e "\n${BLUE}Checking Python dependencies...${NC}"

    local pip_cmd="pip3"
    if [ -n "$VIRTUAL_ENV" ]; then
        pip_cmd="pip"
    fi

    if python3 -c "import yaml" 2>/dev/null; then
        local yaml_version=$(python3 -c "import yaml; print(yaml.__version__)" 2>/dev/null || echo "unknown")
        echo -e "${GREEN}✓ PyYAML installed${NC} - version $yaml_version"
        return 0
    else
        echo -e "${RED}✗ PyYAML not installed${NC}"
        NEEDS_PYTHON_DEPS=true
        return 1
    fi
}

# Function to install system tools
install_system_tools() {
    echo -e "\n${YELLOW}Installing required system tools...${NC}"

    # Detect OS
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command_exists apt-get; then
            echo "Detected Debian/Ubuntu system"
            echo "Running: sudo apt-get update && sudo apt-get install -y masscan nmap ssh-audit"
            sudo apt-get update
            sudo apt-get install -y masscan nmap ssh-audit
        elif command_exists yum; then
            echo "Detected RedHat/CentOS system"
            echo "Running: sudo yum install -y masscan nmap"
            sudo yum install -y masscan nmap
            echo -e "${YELLOW}Note: ssh-audit may need to be installed via pip3 install ssh-audit${NC}"
        else
            echo -e "${RED}Unable to detect package manager. Please install masscan, nmap, and ssh-audit manually.${NC}"
            return 1
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        if command_exists brew; then
            echo "Detected macOS with Homebrew"
            echo "Running: brew install masscan nmap"
            brew install masscan nmap
            echo "Running: pip3 install ssh-audit"
            pip3 install ssh-audit
        else
            echo -e "${RED}Homebrew not found. Please install from https://brew.sh${NC}"
            return 1
        fi
    else
        echo -e "${RED}Unsupported OS: $OSTYPE${NC}"
        return 1
    fi

    # Ask about installing Nuclei (optional)
    echo ""
    echo -e "${BLUE}Nuclei is an optional vulnerability scanner that can enhance scanning.${NC}"
    read -p "Install Nuclei? (requires Go) (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_nuclei
    else
        echo -e "${YELLOW}Skipping Nuclei installation${NC}"
        echo -e "You can install it later from: https://github.com/projectdiscovery/nuclei"
    fi
}

# Function to install Nuclei
install_nuclei() {
    echo -e "\n${BLUE}Installing Nuclei...${NC}"

    # Check if Go is installed
    if ! command_exists go; then
        echo -e "${YELLOW}Go is not installed. Nuclei requires Go for installation.${NC}"
        echo ""
        echo "Installation options:"
        echo "  1. Install Go from https://golang.org/dl/"
        echo "  2. Download pre-built Nuclei binary from https://github.com/projectdiscovery/nuclei/releases"
        echo ""
        read -p "Do you want to download the pre-built binary? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            install_nuclei_binary
        else
            echo -e "${YELLOW}Skipping Nuclei installation${NC}"
        fi
        return
    fi

    echo "Installing Nuclei via Go..."
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

    # Add GOPATH/bin to PATH hint if nuclei still not in path
    if ! command_exists nuclei; then
        local gopath=$(go env GOPATH)
        echo -e "${YELLOW}Nuclei installed but not found in PATH${NC}"
        echo "Add this to your ~/.bashrc or ~/.zshrc:"
        echo -e "${GREEN}  export PATH=\$PATH:$gopath/bin${NC}"
        echo ""
        echo "Then run: source ~/.bashrc (or ~/.zshrc)"
    else
        echo -e "${GREEN}✓ Nuclei installed successfully${NC}"
    fi
}

# Function to install pre-built Nuclei binary
install_nuclei_binary() {
    echo -e "\n${BLUE}Downloading pre-built Nuclei binary...${NC}"

    local os_type=""
    local arch=$(uname -m)

    # Detect OS
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        os_type="linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        os_type="macOS"
    else
        echo -e "${RED}Unsupported OS for binary download: $OSTYPE${NC}"
        return 1
    fi

    # Map architecture
    case $arch in
        x86_64)
            arch="amd64"
            ;;
        arm64|aarch64)
            arch="arm64"
            ;;
        *)
            echo -e "${RED}Unsupported architecture: $arch${NC}"
            return 1
            ;;
    esac

    local download_url="https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_${os_type}_${arch}.zip"
    local temp_dir=$(mktemp -d)

    echo "Downloading from: $download_url"
    if command_exists curl; then
        curl -L -o "$temp_dir/nuclei.zip" "$download_url"
    elif command_exists wget; then
        wget -O "$temp_dir/nuclei.zip" "$download_url"
    else
        echo -e "${RED}Neither curl nor wget found. Cannot download binary.${NC}"
        rm -rf "$temp_dir"
        return 1
    fi

    # Extract and install
    if command_exists unzip; then
        unzip -q "$temp_dir/nuclei.zip" -d "$temp_dir"
        chmod +x "$temp_dir/nuclei"

        # Try to install to /usr/local/bin
        if sudo mv "$temp_dir/nuclei" /usr/local/bin/nuclei 2>/dev/null; then
            echo -e "${GREEN}✓ Nuclei installed to /usr/local/bin/nuclei${NC}"
        else
            # Fallback to ~/.local/bin
            mkdir -p "$HOME/.local/bin"
            mv "$temp_dir/nuclei" "$HOME/.local/bin/nuclei"
            echo -e "${GREEN}✓ Nuclei installed to ~/.local/bin/nuclei${NC}"
            echo -e "${YELLOW}Add ~/.local/bin to your PATH if not already:${NC}"
            echo -e "${GREEN}  export PATH=\$PATH:\$HOME/.local/bin${NC}"
        fi
    else
        echo -e "${RED}unzip not found. Cannot extract binary.${NC}"
        rm -rf "$temp_dir"
        return 1
    fi

    rm -rf "$temp_dir"
}

# Function to setup virtual environment
setup_venv() {
    echo -e "\n${BLUE}Setting up Python virtual environment...${NC}"

    if [ -d "venv" ]; then
        echo -e "${YELLOW}Virtual environment already exists${NC}"
        read -p "Recreate it? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf venv
        else
            return 0
        fi
    fi

    echo "Creating virtual environment..."
    python3 -m venv venv

    echo -e "${GREEN}✓ Virtual environment created${NC}"
    echo ""
    echo -e "${YELLOW}To activate the virtual environment, run:${NC}"
    echo -e "${GREEN}  source venv/bin/activate${NC}"
    echo ""
}

# Function to install Python dependencies
install_python_deps() {
    echo -e "\n${BLUE}Installing Python dependencies...${NC}"

    local pip_cmd="pip3"
    if [ -n "$VIRTUAL_ENV" ]; then
        pip_cmd="pip"
    fi

    echo "Running: $pip_cmd install -r requirements.txt"
    $pip_cmd install -r requirements.txt

    echo -e "${GREEN}✓ Python dependencies installed${NC}"
}

# Function to setup sudo for masscan
setup_masscan_sudo() {
    echo -e "\n${BLUE}Masscan requires sudo privileges...${NC}"

    if [ -f "/etc/sudoers.d/masscan" ]; then
        echo -e "${GREEN}✓ Masscan sudoers file already exists${NC}"
        return 0
    fi

    echo ""
    echo -e "${YELLOW}For automated scanning, masscan needs passwordless sudo access.${NC}"
    echo "This script can create a sudoers file for you."
    echo ""
    read -p "Create sudoers file for masscan? (y/n) " -n 1 -r
    echo

    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Skipping sudoers setup. You'll need to enter your password when scanning.${NC}"
        return 0
    fi

    local username=$(whoami)
    local masscan_path=$(which masscan)

    echo "Creating /etc/sudoers.d/masscan..."
    echo "$username ALL=(root) NOPASSWD: $masscan_path" | sudo tee /etc/sudoers.d/masscan > /dev/null
    sudo chmod 0440 /etc/sudoers.d/masscan

    echo -e "${GREEN}✓ Sudoers file created${NC}"
}

# Function to create example config if needed
setup_config() {
    echo -e "\n${BLUE}Checking configuration...${NC}"

    if [ ! -f "config.yaml" ]; then
        echo -e "${RED}✗ config.yaml not found${NC}"
        echo "Please ensure config.yaml exists in the current directory"
        return 1
    fi

    echo -e "${GREEN}✓ config.yaml found${NC}"

    # Check if targets file exists
    if [ ! -f "targets.csv" ] && [ ! -f "targets-full.csv" ]; then
        echo -e "${YELLOW}! No targets.csv file found${NC}"
        echo "  You can copy targets.csv.example to get started:"
        echo "  cp targets.csv.example targets.csv"
    else
        echo -e "${GREEN}✓ Targets CSV file found${NC}"
    fi
}

# Main setup flow
main() {
    # Check Python version
    if ! check_python_version; then
        echo -e "\n${RED}Python 3.8+ is required. Please upgrade Python and try again.${NC}"
        exit 1
    fi

    # Check system tools
    check_system_tools || true

    # If check-only mode, exit here
    if [ "$CHECK_ONLY" = true ]; then
        check_python_deps || true
        echo ""
        if [ "$NEEDS_SYSTEM_TOOLS" = false ] && [ "$NEEDS_PYTHON_DEPS" = false ]; then
            echo -e "${GREEN}All dependencies are installed!${NC}"
            exit 0
        else
            echo -e "${YELLOW}Some dependencies are missing. Run without --check-only to install.${NC}"
            exit 1
        fi
    fi

    # Install system tools if needed
    if [ "$NEEDS_SYSTEM_TOOLS" = true ]; then
        echo ""
        read -p "Install missing system tools? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            install_system_tools
        else
            echo -e "${YELLOW}Skipping system tools installation${NC}"
            echo "You'll need to install masscan, nmap, and ssh-audit manually"
        fi
    fi

    # Decide on virtual environment
    if [ -z "$USE_VENV" ]; then
        echo ""
        echo "Do you want to use a Python virtual environment?"
        echo "  - Recommended for development and isolation"
        echo "  - Not required if installing system-wide"
        read -p "Use virtual environment? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            USE_VENV="yes"
        else
            USE_VENV="no"
        fi
    fi

    # Setup virtual environment if requested
    if [ "$USE_VENV" = "yes" ]; then
        setup_venv
        # Activate it for the rest of the script
        if [ -f "venv/bin/activate" ]; then
            source venv/bin/activate
        fi
    fi

    # Check Python dependencies
    check_python_deps || true

    # Install Python dependencies if needed
    if [ "$NEEDS_PYTHON_DEPS" = true ]; then
        install_python_deps
    fi

    # Setup masscan sudo
    if command_exists masscan; then
        setup_masscan_sudo
    fi

    # Setup config
    setup_config

    # Final summary
    echo ""
    echo -e "${BLUE}================================================${NC}"
    echo -e "${GREEN}Setup complete!${NC}"
    echo -e "${BLUE}================================================${NC}"
    echo ""

    if [ "$USE_VENV" = "yes" ] && [ -z "$VIRTUAL_ENV" ]; then
        echo -e "${YELLOW}⚠️  Important: Activate the virtual environment${NC}"
        echo ""
        echo "Run this command to activate the venv:"
        echo -e "${GREEN}  source venv/bin/activate${NC}"
        echo ""
        echo "Then you can run the scanner:"
        echo -e "${GREEN}  python3 knock_knock.py --targets targets.csv${NC}"
        echo ""
        echo -e "${BLUE}Tip: Add this to your shell to make it easy:${NC}"
        echo -e "  alias knockknock-activate='cd $(pwd) && source venv/bin/activate'"
    elif [ "$USE_VENV" = "yes" ] && [ -n "$VIRTUAL_ENV" ]; then
        echo -e "${GREEN}✓ Virtual environment is already activated!${NC}"
        echo ""
        echo "You can now run the scanner:"
        echo -e "${GREEN}  python3 knock_knock.py --targets targets.csv${NC}"
    else
        echo "You can now run the scanner:"
        echo -e "${GREEN}  python3 knock_knock.py --targets targets.csv${NC}"
    fi

    echo ""
    echo "For help:"
    echo -e "${GREEN}  python3 knock_knock.py --help${NC}"
    echo ""
}

# Run main function
main
