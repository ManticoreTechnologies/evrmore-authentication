# Evrmore Authentication

<div align="center">
  <img src="https://raw.githubusercontent.com/EvrmoreOrg/evrmore-graphics/master/evrmore-logos/evr_logo_blue_200.png" alt="Evrmore" width="200"/>
  <br><br>
  
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
  [![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/downloads/)
  [![PyPI](https://img.shields.io/badge/PyPI-v0.3.0-blue?style=for-the-badge&logo=pypi&logoColor=white)](https://pypi.org/project/evrmore-authentication/)
  
  <h3>Secure blockchain-based authentication using Evrmore wallet signatures</h3>
</div>

<div align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#api-endpoints">API</a> •
  <a href="#documentation">Docs</a>
</div>

---

## Features

<div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 20px; margin: 20px 0;">
  <div style="border: 1px solid #ddd; border-radius: 10px; padding: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
    <h3 style="color: #5275c8;">🔐 Blockchain-based Auth</h3>
    <p>Secure authentication using cryptographic signatures from Evrmore wallets - no passwords needed!</p>
  </div>
  
  <div style="border: 1px solid #ddd; border-radius: 10px; padding: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
    <h3 style="color: #5275c8;">🔄 Challenge-Response</h3>
    <p>Generated signature challenges ensure secure, replay-proof authentication</p>
  </div>
  
  <div style="border: 1px solid #ddd; border-radius: 10px; padding: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
    <h3 style="color: #5275c8;">⚙️ Easy Setup</h3>
    <p>SQLite backend and auto-configuration make deployment simple</p>
  </div>
</div>

## Installation

```bash
pip3 install evrmore-authentication
```

## Quick Start

<div style="background-color: #f8f9fa; border-radius: 10px; padding: 20px; margin: 20px 0; border-left: 5px solid #5275c8;">

### Basic Example

```python
from evrmore_authentication import EvrmoreAuth

# Initialize auth system
auth = EvrmoreAuth()

# Generate a challenge for a user to sign
challenge = auth.generate_challenge(evrmore_address="EVRaddressHere")

# Verify the signature and create a session
session = auth.authenticate(
    evrmore_address="EVRaddressHere", 
    challenge=challenge,
    signature="signatureFromWallet"
)

# Use the token for subsequent requests
token = session.token
print(f"User authenticated! Token: {token[:20]}...")

# Later, validate the token
auth.validate_token(token)

# Get user information
user = auth.get_user_by_token(token)

# Logout (invalidate token)
auth.invalidate_token(token)
```

### Authentication Flow

<img src="https://mermaid.ink/img/pako:eNptkU1PwzAMhv9KlHPR9g-gF8SAAF040Q0JcQh1qJVmIXGXD2mT-O8kbScGu8V-_NrxG-eJWKuR5KRC-KXygUPryDAF3aPvcUkZZW1Y8VBLroXcBPQrjMbMCt2DPmARcIxeKKkw8p-d6B4MRFvCJjBCU7sI0YPp0Y07NrYGD3vg0lmmMpblrXQcVq85XQwH9zDH3XOUspMWyBJ-xhc2b3IkJ2Jm4dxr7-S1lMpvMaAzCuJfM64UyE3V0-xvqGxgreBm0juvjfgMkNeBx-rAG-8D75I6Vb-fSe5iK_k7Vn9cGcQPJSWE0R1W5w5c8aLsZ1Q9kXwtDV5HVR_IM8nmrKhZNuVplrAsK8qcT7KCQsmmLM8mbJrn03TKiglLSPbx4TQmX_1MX04?type=png" alt="Authentication Flow" style="max-width: 100%; height: auto; display: block; margin: 20px auto;">

</div>

## API Endpoints

The included API server provides these endpoints:

<table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
  <thead style="background-color: #5275c8; color: white;">
    <tr>
      <th style="padding: 15px; text-align: left;">Endpoint</th>
      <th style="padding: 15px; text-align: left;">Method</th>
      <th style="padding: 15px; text-align: left;">Description</th>
    </tr>
  </thead>
  <tbody>
    <tr style="background-color: #f8f9fa;">
      <td style="padding: 15px; border-top: 1px solid #ddd;"><code>/challenge</code></td>
      <td style="padding: 15px; border-top: 1px solid #ddd;">POST</td>
      <td style="padding: 15px; border-top: 1px solid #ddd;">Generate a challenge for a user</td>
    </tr>
    <tr>
      <td style="padding: 15px; border-top: 1px solid #ddd;"><code>/authenticate</code></td>
      <td style="padding: 15px; border-top: 1px solid #ddd;">POST</td>
      <td style="padding: 15px; border-top: 1px solid #ddd;">Authenticate with a signed challenge</td>
    </tr>
    <tr style="background-color: #f8f9fa;">
      <td style="padding: 15px; border-top: 1px solid #ddd;"><code>/validate</code></td>
      <td style="padding: 15px; border-top: 1px solid #ddd;">GET</td>
      <td style="padding: 15px; border-top: 1px solid #ddd;">Validate a JWT token</td>
    </tr>
    <tr>
      <td style="padding: 15px; border-top: 1px solid #ddd;"><code>/me</code></td>
      <td style="padding: 15px; border-top: 1px solid #ddd;">GET</td>
      <td style="padding: 15px; border-top: 1px solid #ddd;">Get authenticated user information</td>
    </tr>
    <tr style="background-color: #f8f9fa;">
      <td style="padding: 15px; border-top: 1px solid #ddd;"><code>/logout</code></td>
      <td style="padding: 15px; border-top: 1px solid #ddd;">POST</td>
      <td style="padding: 15px; border-top: 1px solid #ddd;">Invalidate a JWT token (logout)</td>
    </tr>
  </tbody>
</table>

## Running the Server

```bash
# With the installed package
evrmore-auth-api --host 0.0.0.0 --port 8000

# Or with the provided script
./run_api.py --port 8000

# Run the demo web interface
./run_web_demo.py --port 5000 --api-url http://localhost:8000
```

## Documentation

<div style="display: flex; flex-wrap: wrap; gap: 16px; margin: 20px 0;">
  <a href="https://manticoretechnologies.github.io/evrmore-authentication/" style="display: inline-block; padding: 15px 25px; background-color: #5275c8; color: white; text-decoration: none; border-radius: 8px; font-weight: bold; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
    📖 Full Documentation
  </a>
  <a href="https://github.com/manticoretechnologies/evrmore-authentication/issues" style="display: inline-block; padding: 15px 25px; background-color: #f8f9fa; color: #333; text-decoration: none; border-radius: 8px; border: 1px solid #ddd; font-weight: bold; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
    🐛 Report Issues
  </a>
</div>

## License

MIT License © 2023-2024 [Manticore Technologies](https://manticore.technology) 