#!/bin/bash

# Enterprise Platform Automation Deployment Engine
RESET="\x1b[0m"
BOLD="\x1b[1m"
GREEN="\x1b[32m"
RED="\x1b[31m"
CYAN="\x1b[36m"
YELLOW="\x1b[33m"

echo -e "${CYAN}======================================================================${RESET}"
echo -e "${BOLD}${CYAN}⚙️  STARTING ENTERPRISE PLATFORM AUTOMATED ENVIRONMENT DEPLOYMENT${RESET}"
echo -e "${CYAN}======================================================================${RESET}"

# 1. Install Node.js standard node packages listed in manifest
echo -e "\n${YELLOW}[*] Installing project node modules via NPM...${RESET}"
npm install
if [ $? -ne 0 ]; then
    echo -e "${RED}[ Hisss ] Node packages installation failed. Check network parameters.${RESET}"
    exit 1
fi
echo -e "${GREEN}[✔] Node modules successfully mapped.${RESET}"

# 2. Critical Fix: Install Playwright Chromium binaries and OS-level shared libraries (.so files)
echo -e "\n${YELLOW}[*] Downloading Chromium binaries and updating OS dependencies...${RESET}"
npx playwright install chromium
if [ $? -ne 0 ]; then
    echo -e "${RED}[❌] Failed to fetch target browser layers.${RESET}"
    exit 1
fi

echo -e "${YELLOW}[*] Injecting missing Linux system packages (libgbm, libasound, etc.)...${RESET}"
sudo npx playwright install-deps
echo -e "${GREEN}[✔] Browser layers and system libraries successfully configured.${RESET}"

# 3. Synchronize database states and re-compile structural mapping client
echo -e "\n${YELLOW}[*] Initializing graph relational migrations via Prisma Engine...${RESET}"
npx prisma db push --schema=./packages/database/prisma/schema.prisma
npx prisma generate --schema=./packages/database/prisma/schema.prisma
if [ $? -ne 0 ]; then
    echo -e "${RED}[❌] Prisma context mapping sync failed.${RESET}"
    exit 1
fi

echo -e "\n${GREEN}======================================================================${RESET}"
echo -e "${BOLD}${GREEN}✔ ENVIRONMENT PORTABILITY CONFIGURATION COMPLETED SUCCESSFULLY!${RESET}"
echo -e "${GREEN}======================================================================${RESET}"
echo -e "👉 Execute scans now using: ${BOLD}${YELLOW}npm start -- <target_or_file>${RESET}"
echo -e "👉 Analyze graph vectors using: ${BOLD}${YELLOW}npm run batch${RESET}\n"
