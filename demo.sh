#!/bin/bash
# Evrmore Authentication API Demo Script
# Created by Manticore Technologies - https://manticore.technology

# Terminal colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Print with color
print_green() { echo -e "${GREEN}$1${NC}"; }
print_yellow() { echo -e "${YELLOW}$1${NC}"; }
print_red() { echo -e "${RED}$1${NC}"; }
print_blue() { echo -e "${BLUE}$1${NC}"; }
print_cyan() { echo -e "${CYAN}$1${NC}"; }

# Print section header
print_header() {
    echo
    print_blue "====================================================================="
    print_blue "  $1"
    print_blue "====================================================================="
}

# Print API response
print_response() {
    echo -e "${CYAN}Response:${NC}"
    echo "$1" | jq -C '.'
    echo
}

# Set working directory to script location
cd "$(dirname "$0")" || exit

# Check if server is running
PORT=${1:-8000}
SERVER_URL="http://localhost:$PORT"

print_header "Evrmore Authentication API Demo"
print_yellow "Testing server at $SERVER_URL"

if ! curl -s "$SERVER_URL" > /dev/null; then
    print_red "Error: Server not running at $SERVER_URL"
    print_yellow "Please start the server first with: ./start_auth_server.sh"
    exit 1
fi

# Check if evrmore-cli is available
if ! command -v evrmore-cli &> /dev/null; then
    print_red "Error: evrmore-cli not found."
    print_yellow "This demo requires evrmore-cli to sign challenges."
    print_yellow "Please install Evrmore Core and try again."
    exit 1
fi

# Check if Evrmore node is running
if ! evrmore-cli getblockchaininfo &> /dev/null; then
    print_red "Error: Evrmore node is not running or not accessible."
    print_yellow "Please start your Evrmore node and try again."
    exit 1
fi

# Get a new address for the demo
print_header "1. Getting a new Evrmore address for testing"
EVRMORE_ADDRESS=$(evrmore-cli getnewaddress)
print_green "✓ New Evrmore address: $EVRMORE_ADDRESS"

# Step 1: Generate a challenge
print_header "2. Generate a challenge"
print_yellow "Sending request to generate a challenge for address: $EVRMORE_ADDRESS"

CHALLENGE_RESPONSE=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    -d "{\"evrmore_address\": \"$EVRMORE_ADDRESS\"}" \
    $SERVER_URL/challenge)

print_response "$CHALLENGE_RESPONSE"

# Extract challenge from response
CHALLENGE=$(echo "$CHALLENGE_RESPONSE" | jq -r '.challenge')
print_green "✓ Challenge: $CHALLENGE"

# Step 2: Sign the challenge with Evrmore wallet
print_header "3. Sign the challenge with Evrmore wallet"
print_yellow "Signing challenge with evrmore-cli..."

SIGNATURE=$(evrmore-cli signmessage "$EVRMORE_ADDRESS" "$CHALLENGE")
print_green "✓ Signature: $SIGNATURE"

# Step 3: Authenticate
print_header "4. Authenticate with the signature"
print_yellow "Sending authentication request..."

AUTH_RESPONSE=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    -d "{\"evrmore_address\": \"$EVRMORE_ADDRESS\", \"challenge\": \"$CHALLENGE\", \"signature\": \"$SIGNATURE\"}" \
    $SERVER_URL/authenticate)

print_response "$AUTH_RESPONSE"

# Extract token
TOKEN=$(echo "$AUTH_RESPONSE" | jq -r '.token')
print_green "✓ JWT Token: ${TOKEN:0:20}..."

# Step 4: Validate token
print_header "5. Validate the token"
print_yellow "Validating token..."

VALIDATE_RESPONSE=$(curl -s "$SERVER_URL/validate?token=$TOKEN")
print_response "$VALIDATE_RESPONSE"

IS_VALID=$(echo "$VALIDATE_RESPONSE" | jq -r '.valid')
if [ "$IS_VALID" = "true" ]; then
    print_green "✓ Token is valid"
else
    print_red "✗ Token validation failed"
fi

# Step 5: Get user info
print_header "6. Get user information"
print_yellow "Getting user info with token..."

USER_INFO_RESPONSE=$(curl -s -H "Authorization: Bearer $TOKEN" "$SERVER_URL/me")
print_response "$USER_INFO_RESPONSE"

USER_ID=$(echo "$USER_INFO_RESPONSE" | jq -r '.id')
print_green "✓ User ID: $USER_ID"

# Step 6: Logout
print_header "7. Logout (invalidate token)"
print_yellow "Logging out..."

LOGOUT_RESPONSE=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    -d "{\"token\": \"$TOKEN\"}" \
    $SERVER_URL/logout)

print_response "$LOGOUT_RESPONSE"

SUCCESS=$(echo "$LOGOUT_RESPONSE" | jq -r '.success')
if [ "$SUCCESS" = "true" ]; then
    print_green "✓ Logout successful"
else
    print_red "✗ Logout failed"
fi

# Step 7: Try to access protected resource after logout
print_header "8. Try to access user info after logout"
print_yellow "Getting user info with invalidated token..."

INVALID_ACCESS_RESPONSE=$(curl -s -H "Authorization: Bearer $TOKEN" "$SERVER_URL/me")
print_response "$INVALID_ACCESS_RESPONSE"

print_green "✓ Complete! The demo has successfully shown the full authentication flow."
print_header "Demo Completed" 