#!/bin/bash
# Setup script for Secure Chat System

echo "═══════════════════════════════════════════════════════════"
echo "  Secure Chat System - Setup Script"
echo "═══════════════════════════════════════════════════════════"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo -e "${YELLOW}[*] Creating virtual environment...${NC}"
    python3 -m venv .venv
fi

# Activate virtual environment
echo -e "${YELLOW}[*] Activating virtual environment...${NC}"
source .venv/bin/activate

# Install requirements
echo -e "${YELLOW}[*] Installing requirements...${NC}"
pip install -q -r requirements.txt

# Generate certificates
echo -e "\n${YELLOW}[*] Generating PKI certificates...${NC}"

# Check if certificates already exist
if [ -f "certs/ca-cert.pem" ]; then
    echo -e "${YELLOW}[!] Certificates already exist. Skipping generation.${NC}"
    echo -e "${YELLOW}[!] Delete certs/*.pem to regenerate.${NC}"
else
    # Generate CA
    echo -e "${GREEN}[+] Generating Root CA...${NC}"
    python scripts/gen_ca.py --name "FAST-NU Root CA" --output certs --days 3650
    
    # Generate server certificate
    echo -e "\n${GREEN}[+] Generating server certificate...${NC}"
    python scripts/gen_cert.py --cn "securechat.server" --out certs/server --type server --ca-cert certs/ca-cert.pem --ca-key certs/ca-key.pem --days 365
    
    # Generate client certificate
    echo -e "\n${GREEN}[+] Generating client certificate...${NC}"
    python scripts/gen_cert.py --cn "securechat.client" --out certs/client --type client --ca-cert certs/ca-cert.pem --ca-key certs/ca-key.pem --days 365
    
    echo -e "\n${GREEN}[+] Certificates generated successfully!${NC}"
fi

# Check if .env exists
if [ ! -f ".env" ]; then
    echo -e "\n${YELLOW}[*] Creating .env file from template...${NC}"
    cp .env.example .env
    echo -e "${GREEN}[+] .env file created. Please update with your database credentials.${NC}"
else
    echo -e "\n${YELLOW}[!] .env file already exists.${NC}"
fi

# Initialize database
echo -e "\n${YELLOW}[*] Do you want to initialize the database now? (y/n)${NC}"
read -p "> " init_db

if [ "$init_db" = "y" ] || [ "$init_db" = "Y" ]; then
    echo -e "${YELLOW}[*] Initializing database...${NC}"
    python -m app.storage.db --init
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[+] Database initialized successfully!${NC}"
    else
        echo -e "${RED}[!] Database initialization failed. Please check your .env configuration.${NC}"
    fi
else
    echo -e "${YELLOW}[!] Skipping database initialization. Run 'python -m app.storage.db --init' later.${NC}"
fi

echo -e "\n═══════════════════════════════════════════════════════════"
echo -e "${GREEN}Setup complete!${NC}"
echo -e "═══════════════════════════════════════════════════════════"
echo -e "\nNext steps:"
echo -e "1. Update ${YELLOW}.env${NC} with your MySQL credentials"
echo -e "2. Run ${YELLOW}'python -m app.storage.db --init'${NC} to initialize database"
echo -e "3. Start server: ${YELLOW}'python -m app.server'${NC}"
echo -e "4. Start client: ${YELLOW}'python -m app.client'${NC}"
echo ""
