#!/usr/bin/env python3
"""
Evrmore Authentication Installer
--------------------------------
Installation script for Evrmore Authentication system.
"""

import os
import sys
import shutil
import subprocess
import logging
import getpass
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("installer")

# Systemd service template
SYSTEMD_SERVICE_TEMPLATE = '''
[Unit]
Description=Evrmore Accounts API Gunicorn Service
After=network.target

[Service]
User={user}
WorkingDirectory={work_dir}
ExecStart=/bin/bash -c 'source {venv_path}/bin/activate && python3 -m scripts.run_api_server --host {host} --port {port}'
Restart=always
Environment="PYTHONUNBUFFERED=1"

[Install]
WantedBy=multi-user.target
'''

def install_system(install_systemd=False, db_path=None, host="0.0.0.0", port=8000, 
                  init_db=True, register_client=False):
    """
    Install the Evrmore Authentication system.
    
    Args:
        install_systemd (bool): Whether to install as a systemd service
        db_path (str): Custom database path
        host (str): Host to bind to
        port (int): Port to bind to
        init_db (bool): Whether to initialize the database
        register_client (bool): Whether to register a default OAuth client
    """
    logger.info("Starting Evrmore Authentication installation...")
    
    # Get the current directory (package root)
    package_dir = Path(__file__).resolve().parent.parent.parent
    
    # 1. Create data directory if it doesn't exist
    data_dir = package_dir / "evrmore_authentication" / "data"
    if not data_dir.exists():
        logger.info(f"Creating data directory: {data_dir}")
        data_dir.mkdir(parents=True, exist_ok=True)
        
    # 2. Set up the .env file if it doesn't exist
    env_file = package_dir / ".env"
    env_example = package_dir / ".env.example"
    
    if not env_file.exists() and env_example.exists():
        logger.info("Creating .env file from example...")
        shutil.copy(env_example, env_file)
        
        # Update database path if specified
        if db_path:
            update_env_file(env_file, "SQLITE_DB_PATH", db_path)
    
    # 3. Initialize the database
    if init_db:
        logger.info("Initializing database...")
        try:
            subprocess.run(
                [sys.executable, "-m", "scripts.db_manage", "init"],
                check=True,
                cwd=package_dir
            )
            logger.info("Database initialized successfully.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to initialize database: {e}")
            
    # 4. Register default OAuth client if requested
    if register_client:
        logger.info("Registering default OAuth client...")
        try:
            subprocess.run(
                [
                    sys.executable, 
                    "-m", 
                    "scripts.register_oauth_client",
                    "register",
                    "--name", "Default Client",
                    "--redirects", f"http://localhost:{port}/callback",
                    "--scopes", "profile,email"
                ],
                check=True,
                cwd=package_dir,
                capture_output=True,
                text=True
            )
            logger.info("Default OAuth client registered successfully.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to register OAuth client: {e}")
            logger.error(f"Output: {e.stdout}")
            logger.error(f"Error: {e.stderr}")
    
    # 5. Install systemd service if requested
    if install_systemd:
        install_systemd_service(package_dir, host, port)
        
    logger.info("Evrmore Authentication installation completed!")
    logger.info(f"You can now run the server with: python3 -m scripts.run_api_server --host {host} --port {port}")

def update_env_file(env_file, key, value):
    """Update a key in the .env file."""
    with open(env_file, "r") as f:
        lines = f.readlines()
        
    updated = False
    for i, line in enumerate(lines):
        if line.strip().startswith(f"{key}="):
            lines[i] = f"{key}={value}\n"
            updated = True
            break
            
    if not updated:
        lines.append(f"{key}={value}\n")
        
    with open(env_file, "w") as f:
        f.writelines(lines)

def install_systemd_service(package_dir, host, port):
    """Install the systemd service."""
    logger.info("Installing systemd service...")
    
    # Determine if we're in a virtual environment
    in_venv = sys.prefix != sys.base_prefix
    venv_path = sys.prefix if in_venv else f"{package_dir}/venv"
    
    # Get the current user
    user = getpass.getuser()
    
    # Generate the service file content
    service_content = SYSTEMD_SERVICE_TEMPLATE.format(
        user=user,
        work_dir=package_dir,
        venv_path=venv_path,
        host=host,
        port=port
    )
    
    # Write the service file
    service_file = Path("/tmp/evrmore-auth.service")
    with open(service_file, "w") as f:
        f.write(service_content.strip())
    
    logger.info(f"Service file created: {service_file}")
    logger.info("To install the service, run the following commands:")
    logger.info("  sudo cp /tmp/evrmore-auth.service /etc/systemd/system/")
    logger.info("  sudo systemctl daemon-reload")
    logger.info("  sudo systemctl enable evrmore-auth.service")
    logger.info("  sudo systemctl start evrmore-auth.service")

if __name__ == "__main__":
    # If run directly, show usage
    print("This script should be run via the CLI command: evrmore_authentication install")
    print("For more options, run: evrmore_authentication install --help")