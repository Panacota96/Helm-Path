#!/bin/bash

# --- HELM-PATH DEPLOYMENT SCRIPT ---
# The Scribe of the Watcher is ready to forge your tools.

# Color definitions
GOLD='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GOLD}🛡️  Forging the Watcher's Tools: Helm-Path Deployment${NC}"

# 1. Structure Check: Implementing src-layout
if [ ! -d "src" ]; then
    echo -e "${BLUE}📘 Creating the 'src' sanctuary...${NC}"
    mkdir -p src
fi

if [ -d "helm_path" ]; then
    echo -e "${BLUE}📘 Moving 'helm_path' to the 'src' sanctuary...${NC}"
    mv helm_path src/
fi

# 2. Dependency Check: Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Desecration: Docker is missing. Please install it to commence your vigil.${NC}"
    exit 1
fi

# 3. Dependency Check: Ollama (Optional but recommended for the Scribe)
if ! command -v ollama &> /dev/null; then
    echo -e "${CYAN}💡 Note: Ollama is not found. The Scribe will need it to chronicle your deeds.${NC}"
fi

# 4. Installation
echo -e "${BLUE}🔨 Installing Helm-Path globally...${NC}"
python3 -m pip install . --break-system-packages

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Helm-Path has been forged and installed successfully!${NC}"
    echo -e "${GOLD}👁️  Run 'helm-path --help' to see the Watcher's Eye in action.${NC}"
else
    echo -e "${RED}❌ Failed to forge Helm-Path. Check the scrolls (logs) above.${NC}"
    exit 1
fi
