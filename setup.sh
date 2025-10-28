#!/bin/bash
# Setup script for XSS Verification Agent with Docker support

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}=== $1 ===${NC}"
}

print_header "XSS Verification Agent Setup"
echo

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    print_status "Detected OS: $OS"
else
    print_error "Cannot detect OS. This script supports Arch Linux, Ubuntu, and derivatives."
    exit 1
fi

# Check Python version
python_version=$(python3 --version 2>&1 | grep -oE '[0-9]+\.[0-9]+')
required_version="3.10"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    print_error "Python 3.10+ is required. Found: Python $python_version"
    exit 1
else
    print_status "Python $python_version detected ✅"
fi

# Install Docker if not present
if ! command -v docker &> /dev/null; then
    print_warning "Docker is not installed. Installing Docker..."
    
    case "$OS" in
        *"Arch"*)
            print_status "Installing Docker on Arch Linux..."
            sudo pacman -S --noconfirm docker docker-compose
            ;;
        *"Ubuntu"*|*"Debian"*)
            print_status "Installing Docker on Ubuntu/Debian..."
            sudo apt-get update
            sudo apt-get install -y docker.io docker-compose
            ;;
        *"Fedora"*|*"CentOS"*|*"Red Hat"*)
            print_status "Installing Docker on Red Hat based system..."
            sudo dnf install -y docker docker-compose
            ;;
        *)
            print_error "Unsupported OS for automatic Docker installation: $OS"
            print_error "Please install Docker manually: https://docs.docker.com/get-docker/"
            exit 1
            ;;
    esac
    
    # Add user to docker group
    print_status "Adding user to docker group..."
    sudo usermod -aG docker $USER
    
    # Enable and start Docker service
    print_status "Enabling and starting Docker service..."
    sudo systemctl enable docker
    sudo systemctl start docker
    
    print_warning "Docker has been installed. You may need to log out and back in for group changes to take effect."
    print_warning "If Docker commands fail, try: newgrp docker"
else
    print_status "Docker is already installed ✅"
fi

# Check Docker Compose
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null 2>&1; then
    print_warning "Docker Compose not found. Installing..."
    
    case "$OS" in
        *"Arch"*)
            sudo pacman -S --noconfirm docker-compose
            ;;
        *"Ubuntu"*|*"Debian"*)
            sudo apt-get install -y docker-compose
            ;;
        *"Fedora"*|*"CentOS"*|*"Red Hat"*)
            sudo dnf install -y docker-compose
            ;;
        *)
            # Install via pip as fallback
            pip3 install docker-compose
            ;;
    esac
else
    print_status "Docker Compose is available ✅"
fi

# Ensure Docker is running
if ! docker ps &> /dev/null 2>&1; then
    print_status "Starting Docker daemon..."
    sudo systemctl start docker
    
    # Wait a moment for Docker to start
    sleep 3
    
    if ! docker ps &> /dev/null 2>&1; then
        print_error "Docker daemon failed to start. Please check Docker installation."
        print_error "Try: sudo systemctl status docker"
        exit 1
    fi
fi

print_status "Docker daemon is running ✅"

# Create virtual environment
print_header "Setting up Python Environment"
print_status "Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install dependencies
print_status "Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Install Playwright browsers (for local development) - Skip on unsupported OS
if [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]]; then
    print_status "Installing Playwright browsers for local development..."
    playwright install chromium
    playwright install-deps chromium
else
    print_warning "Skipping local Playwright installation on $OS (unsupported)"
    print_status "Playwright will run inside Docker container instead ✅"
fi

# Pull Nuclei Docker image
print_status "Pulling Nuclei Docker image..."
docker pull projectdiscovery/nuclei:latest

# Build Docker image for XSS Agent
print_header "Building Docker Environment"
print_status "Building XSS Agent Docker image..."
docker build -t xss-agent .

# Test Docker setup
print_status "Testing Docker setup..."
if docker run --rm xss-agent python --version > /dev/null 2>&1; then
    print_status "Docker image built successfully ✅"
else
    print_error "Docker image build failed"
    exit 1
fi

# Create necessary directories
print_header "Setting up Directories and Permissions"
print_status "Creating output directories..."
mkdir -p screenshots
mkdir -p logs  
mkdir -p results
mkdir -p nuclei-templates
mkdir -p nuclei-output

# Set executable permissions
print_status "Setting executable permissions..."
chmod +x xss_verification_agent.py
chmod +x run-docker.sh

# Set proper ownership for output directories
print_status "Setting directory permissions..."
chmod 755 screenshots logs results nuclei-templates nuclei-output

print_header "Setup Complete!"
echo
print_status "XSS Verification Agent is ready! You can run it in several ways:"
echo
echo "🐳 Docker (Recommended for Arch Linux):"
echo "  ./run-docker.sh 'http://target-url.com'"
echo
echo "🐙 Docker Compose:"
echo "  TARGET_URL='http://target-url.com' docker-compose up"
echo
echo "🐍 Local Python (if Playwright works):"
echo "  1. source venv/bin/activate"
echo "  2. python xss_verification_agent.py 'http://target-url.com'"
echo
echo "📁 Output locations:"
echo "  • screenshots/ - Screenshot evidence"
echo "  • logs/ - Detailed execution logs"
echo "  • results/ - JSON results files"
echo
print_warning "Optional: Set AWS credentials for LLM support:"
echo "  export AWS_REGION=us-east-1"
echo "  export AWS_ACCESS_KEY_ID=your_key"
echo "  export AWS_SECRET_ACCESS_KEY=your_secret"
echo
print_status "If you installed Docker for the first time, you may need to:"
print_status "1. Log out and back in, OR"
print_status "2. Run: newgrp docker"