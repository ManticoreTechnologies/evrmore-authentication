#!/usr/bin/env python3
"""
Evrmore Authentication OAuth Client Registration Tool
--------------------------------------------
Manticore Technologies - https://manticore.technology

This script registers a new OAuth client for the Evrmore Authentication system.
"""

import os
import sys
import logging
from pathlib import Path

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("evrmore-oauth-register")

# Add the project root to sys.path if needed
project_root = Path(__file__).parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

# Import necessary modules
from evrmore_authentication.models import OAuthClient

def register_client(client_name, redirect_uris, client_uri=None, scopes="profile", response_types="code"):
    """Register a new OAuth client."""
    try:
        client = OAuthClient.create(
            client_name=client_name,
            redirect_uris=redirect_uris,
            client_uri=client_uri,
            allowed_scopes=scopes,
            allowed_response_types=response_types
        )
        
        logger.info(f"Successfully registered new OAuth client:")
        logger.info(f"  - Name: {client.client_name}")
        logger.info(f"  - Client ID: {client.client_id}")
        logger.info(f"  - Client Secret: {client.client_secret}")
        logger.info(f"  - Redirect URIs: {client.redirect_uris}")
        logger.info(f"  - Allowed Scopes: {client.allowed_scopes}")
        logger.info(f"  - Allowed Response Types: {client.allowed_response_types}")
        
        return client
    except Exception as e:
        logger.error(f"Error registering OAuth client: {str(e)}")
        return None

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Register a new OAuth client")
    parser.add_argument("--name", required=True, help="Client application name")
    parser.add_argument("--redirects", required=True, help="Comma-separated list of redirect URIs")
    parser.add_argument("--uri", help="Client application URI")
    parser.add_argument("--scopes", default="profile", help="Comma-separated list of allowed scopes")
    parser.add_argument("--response-types", default="code", help="Comma-separated list of allowed response types")
    
    args = parser.parse_args()
    
    client = register_client(
        client_name=args.name,
        redirect_uris=args.redirects,
        client_uri=args.uri,
        scopes=args.scopes,
        response_types=args.response_types
    )
    
    if client:
        print("\nToUpdate the OAuth client in your .env file or environment:")
        print(f"OAUTH_CLIENT_ID={client.client_id}")
        print(f"OAUTH_CLIENT_SECRET={client.client_secret}") 