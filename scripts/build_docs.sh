#!/bin/bash

echo "Building and deploying documentation to GitHub Pages..."

# Ensure we're in the project root directory
cd "$(dirname "$0")/.." || exit

# Check if mkdocs is installed
if ! command -v mkdocs &> /dev/null; then
    echo "mkdocs not found. Installing..."
    pip3 install mkdocs-material
fi

# Build the static documentation site
echo "Building documentation..."
mkdocs build

# Deploy to GitHub Pages
echo "Deploying to GitHub Pages..."
mkdocs gh-deploy --force

echo "Documentation deployed successfully!"
echo "Visit https://manticoretechnologies.github.io/evrmore-authentication/" 