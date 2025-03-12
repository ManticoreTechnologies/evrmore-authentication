#!/usr/bin/env python3
"""
Evrmore Authentication Web Demo

This is a simple web application that demonstrates the Evrmore authentication flow.
Users can sign in using their Evrmore wallet address and signature.
This demo uses the Evrmore Authentication API server for all backend operations.
"""

import os
import json
import requests
from datetime import datetime, timedelta
from pathlib import Path
from dotenv import load_dotenv
from flask import Flask, request, session, render_template, redirect, url_for, jsonify, flash
from flask_cors import CORS

# Load environment variables from .env file if it exists
env_path = Path(__file__).parent / '.env'
if env_path.exists():
    load_dotenv(env_path)
else:
    print("Warning: No .env file found. Using environment variables or defaults.")

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "evrmore-auth-demo-secret-key")
CORS(app)

# Configuration
API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")
CHALLENGE_EXPIRE_MINUTES = int(os.getenv("CHALLENGE_EXPIRE_MINUTES", "10"))

# API client functions
def api_request(endpoint, method="GET", data=None, headers=None):
    """Make a request to the API server."""
    api_base_url = os.getenv("API_BASE_URL", "http://localhost:8000")
    url = f"{api_base_url}/{endpoint.lstrip('/')}"
    
    default_headers = {"Content-Type": "application/json"}
    if headers:
        default_headers.update(headers)
    
    try:
        print(f"API Request: {method} {url}")
        print(f"Request Data: {data}")
        
        response = requests.request(
            method=method,
            url=url,
            json=data if data else None,
            headers=default_headers,
            timeout=10
        )
        
        # Check for error status codes
        response.raise_for_status()
        
        # Return JSON data
        json_response = response.json()
        print(f"API Response: {json_response}")
        return json_response
    except requests.exceptions.HTTPError as e:
        error_message = f"HTTP Error: {e}"
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_details = e.response.json()
                if 'detail' in error_details:
                    error_message = f"API Error: {error_details['detail']}"
            except:
                pass
        print(f"API Error: {error_message}")
        raise Exception(error_message)
    except Exception as e:
        print(f"Request Error: {str(e)}")
        raise

# Routes
@app.route('/')
def index():
    """Render the home page."""
    static_files = os.listdir(os.path.join(os.path.dirname(__file__), 'static')) if os.path.exists(os.path.join(os.path.dirname(__file__), 'static')) else []
    return render_template('index.html', static_files=static_files)

@app.route('/login')
def login():
    """Render the login page."""
    static_files = os.listdir(os.path.join(os.path.dirname(__file__), 'static')) if os.path.exists(os.path.join(os.path.dirname(__file__), 'static')) else []
    return render_template('login.html', static_files=static_files)

@app.route('/dashboard')
def dashboard():
    """Render the dashboard page for authenticated users."""
    if 'evrmore_address' not in session:
        flash('You must be logged in to view the dashboard', 'danger')
        return redirect(url_for('login'))
    
    static_files = os.listdir(os.path.join(os.path.dirname(__file__), 'static')) if os.path.exists(os.path.join(os.path.dirname(__file__), 'static')) else []
    return render_template('dashboard.html', static_files=static_files)

@app.route('/logout')
def logout():
    """Log out the user by invalidating their token and clearing the session."""
    if 'token' in session:
        try:
            api_request('logout', method='POST', data={'token': session['token']})
        except Exception as e:
            print(f"Error during logout: {str(e)}")
            # Continue with logout even if token invalidation fails
    
    # Clear the session
    session.clear()
    flash('You have been logged out', 'success')
    return redirect(url_for('index'))

@app.route('/api/check-evrmore-node')
def check_evrmore_node():
    """Check if the Evrmore node is available via the API server."""
    try:
        response = api_request('', method='GET')
        return jsonify({'available': response.get('evrmore_node_available', False)})
    except Exception as e:
        print(f"Error checking Evrmore node: {str(e)}")
        return jsonify({'available': False, 'error': str(e)})

@app.route('/api/challenge', methods=['POST'])
def generate_challenge():
    """Generate a challenge for the given Evrmore address via the API server."""
    try:
        data = request.get_json()
        if not data or 'evrmore_address' not in data:
            return jsonify({'status': 'error', 'message': 'Evrmore address is required'}), 400
        
        address = data['evrmore_address']
        
        # Request challenge from API server
        api_data = {
            'evrmore_address': address,
            'expire_minutes': int(os.getenv("CHALLENGE_EXPIRE_MINUTES", "10"))
        }
        
        response = api_request('challenge', method='POST', data=api_data)
        
        # Debug the response
        print(f"Challenge generated: {response.get('challenge')}")
        
        challenge_response = {
            'status': 'success',
            'challenge': response.get('challenge'),
            'expires_at': response.get('expires_at'),
            'address': address
        }
        
        # Store in session for tracking
        session['pending_challenge'] = response.get('challenge')
        session['evrmore_address'] = address
        
        print(f"Challenge response: {challenge_response}")
        
        return jsonify(challenge_response)
    except Exception as e:
        print(f"Error generating challenge: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/authenticate', methods=['POST'])
def authenticate():
    """Authenticate using a challenge and signature via the API server."""
    try:
        data = request.get_json()
        if not data or 'evrmore_address' not in data or 'signature' not in data or 'challenge' not in data:
            return jsonify({'status': 'error', 'message': 'Evrmore address, challenge, and signature are required'}), 400
        
        # Debug log the incoming data
        print(f"Authentication request: address={data['evrmore_address']}, challenge={data['challenge']}")
        print(f"Signature: {data['signature']}")
        
        # Request authentication from API server
        api_data = {
            'evrmore_address': data['evrmore_address'],
            'challenge': data['challenge'],
            'signature': data['signature'],
            'token_expire_minutes': int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
        }
        
        response = api_request('authenticate', method='POST', data=api_data)
        
        # Store authentication info in session
        session['user_id'] = response.get('user_id')
        session['evrmore_address'] = data['evrmore_address']
        session['token'] = response.get('token')
        session['token_expires'] = response.get('expires_at')
        
        return jsonify({
            'status': 'success',
            'token': response.get('token'),
            'expires_at': response.get('expires_at'),
            'user_id': response.get('user_id')
        })
    except Exception as e:
        print(f"Error during authentication: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors."""
    static_files = os.listdir(os.path.join(os.path.dirname(__file__), 'static')) if os.path.exists(os.path.join(os.path.dirname(__file__), 'static')) else []
    return render_template('404.html', static_files=static_files), 404

@app.errorhandler(500)
def internal_server_error(e):
    """Handle 500 errors."""
    print(f"Server error: {str(e)}")
    static_files = os.listdir(os.path.join(os.path.dirname(__file__), 'static')) if os.path.exists(os.path.join(os.path.dirname(__file__), 'static')) else []
    return render_template('500.html', static_files=static_files), 500

if __name__ == '__main__':
    port = int(os.getenv("PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "True").lower() in ['true', '1', 't']
    host = os.getenv("HOST", "0.0.0.0")
    
    print(f"Starting Evrmore Authentication Web Demo on http://{host}:{port}")
    print(f"Using API server at: {API_BASE_URL}")
    app.run(host=host, port=port, debug=debug) 