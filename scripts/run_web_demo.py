#!/usr/bin/env python3
"""
Evrmore Authentication Web Demo

Run this script to start the web demo interface for Evrmore Authentication.

© 2023-2024 Manticore Technologies - manticore.technology
"""

import os
import sys
import logging
import argparse
import subprocess
import requests
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("evrmore-auth-web-demo")

def check_api_server(api_url):
    """Check if the API server is running.
    
    Args:
        api_url: API server URL
        
    Returns:
        bool: True if server is running, False otherwise
    """
    try:
        logger.info(f"Checking API server at {api_url}...")
        response = requests.get(f"{api_url}")
        if response.status_code == 200:
            data = response.json()
            logger.info(f"✅ API server is running: {data.get('name', 'Evrmore Authentication API')}")
            logger.info(f"Evrmore node available: {data.get('evrmore_node_available', False)}")
            return True
        else:
            logger.error(f"❌ API server returned status code {response.status_code}")
            return False
    except Exception as e:
        logger.error(f"❌ Failed to connect to API server: {e}")
        return False

def setup_environment(web_demo_dir, api_url, port):
    """Set up the environment for the web demo.
    
    Args:
        web_demo_dir: Web demo directory
        api_url: API server URL
        port: Web demo port
    """
    env_file = os.path.join(web_demo_dir, ".env")
    if not os.path.exists(env_file):
        logger.info(f"Creating .env file for web demo at {env_file}")
        with open(env_file, "w") as f:
            f.write(f"# Flask configuration\n")
            f.write(f"FLASK_APP=app.py\n")
            f.write(f"FLASK_DEBUG=1\n")
            f.write(f"FLASK_RUN_PORT={port}\n")
            f.write(f"\n# Evrmore Authentication API config\n")
            f.write(f"EVR_AUTH_API_URL={api_url}\n")
        logger.info(f"✅ Created .env file for web demo")
    else:
        logger.info(f"Using existing .env file for web demo")

def install_requirements(web_demo_dir):
    """Install required packages for the web demo.
    
    Args:
        web_demo_dir: Web demo directory
    """
    requirements_file = os.path.join(web_demo_dir, "requirements.txt")
    if os.path.exists(requirements_file):
        logger.info(f"Installing requirements from {requirements_file}")
        result = subprocess.run(
            ["pip3", "install", "-r", requirements_file],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            logger.info(f"✅ Dependencies installed successfully")
        else:
            logger.error(f"❌ Failed to install dependencies")
            logger.error(result.stderr)
            sys.exit(1)
    else:
        logger.info(f"No requirements.txt found, installing default dependencies")
        result = subprocess.run(
            ["pip3", "install", "flask", "requests"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            logger.info(f"✅ Default dependencies installed successfully")
        else:
            logger.error(f"❌ Failed to install default dependencies")
            logger.error(result.stderr)
            sys.exit(1)

def main():
    """Run the web demo."""
    parser = argparse.ArgumentParser(description='Run the Evrmore Authentication Web Demo')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind the web demo to')
    parser.add_argument('--api-url', type=str, default='http://localhost:8000', help='URL of the Evrmore Authentication API')
    
    args = parser.parse_args()
    
    # Check if API server is running
    if not check_api_server(args.api_url):
        logger.error(f"Please start the API server first with './run_api.py --port 8000'")
        logger.error(f"You can also specify a different API URL with --api-url")
        sys.exit(1)
    
    # Locate web demo directory
    web_demo_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "examples",
        "web_auth_demo"
    )
    
    if not os.path.exists(web_demo_dir):
        logger.error(f"❌ Web demo directory not found at {web_demo_dir}")
        sys.exit(1)
    
    # Set up environment and install requirements
    setup_environment(web_demo_dir, args.api_url, args.port)
    install_requirements(web_demo_dir)
    
    # Run the web demo
    logger.info(f"Starting web demo on http://localhost:{args.port}")
    logger.info(f"Press Ctrl+C to stop the server")
    
    os.chdir(web_demo_dir)
    os.environ["FLASK_APP"] = "app.py"
    os.environ["FLASK_DEBUG"] = "1"
    os.environ["FLASK_RUN_PORT"] = str(args.port)
    os.environ["EVR_AUTH_API_URL"] = args.api_url
    
    result = subprocess.run(["flask", "run", "--host", "0.0.0.0", "--port", str(args.port)])
    return result.returncode

if __name__ == "__main__":
    sys.exit(main()) 