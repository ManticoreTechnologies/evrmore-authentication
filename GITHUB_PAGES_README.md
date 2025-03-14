# GitHub Pages Documentation

This document outlines the structure and organization of the GitHub Pages documentation for the Evrmore Authentication project.

## Documentation Structure

The documentation is organized in the following structure:

```
docs/
├── assets/              # Images, logos, and other static assets
├── user-guide/          # User-focused documentation
│   ├── index.md         # Introduction and overview
│   ├── authentication-flow.md  # Explaining the authentication process
│   ├── basic-integration.md    # Getting started with integration
│   ├── oauth-implementation.md # OAuth 2.0 implementation guide
│   ├── debugging.md     # Debugging and advanced features
│   └── troubleshooting.md      # Troubleshooting common issues
├── api-reference/       # Technical API documentation
│   ├── index.md         # API overview
│   ├── core-api.md      # Core authentication API reference
│   ├── oauth-api.md     # OAuth 2.0 API endpoints reference
│   ├── event-hooks.md   # Event hooks system reference
│   └── sqlite.md        # SQLite implementation details
├── examples/            # Code examples
│   ├── index.md         # Overview of examples
│   ├── basic-demo.md    # Basic authentication example
│   ├── fastapi-integration.md # FastAPI integration example
│   └── oauth-client.md  # OAuth 2.0 client example
├── development/         # Developer-focused documentation
│   ├── index.md         # Development overview
│   ├── testing.md       # Testing guidelines
│   ├── contributing.md  # Contribution guidelines
│   └── security.md      # Security best practices
└── index.md             # Main landing page
```

## Key Documentation Features

1. **Comprehensive OAuth Documentation**: Detailed guides on the OAuth 2.0 implementation, including client registration, authorization flow, token management, and troubleshooting.

2. **Authentication Flow Visualization**: Step-by-step explanation of the Evrmore wallet-based authentication process, including challenge generation, signature verification, and token issuance.

3. **Framework Integration Examples**: Samples for integrating with FastAPI, Flask, and Django frameworks.

4. **Advanced Features**: Documentation on event hooks, database extensions, and customization options.

5. **Troubleshooting Guide**: Dedicated section for debugging common issues, with clear solutions and diagnostics.

## Building and Deploying

The documentation is built using MkDocs with the Material theme. To build and deploy:

1. Install required packages:
   ```bash
   pip3 install mkdocs-material
   ```

2. Build the documentation locally:
   ```bash
   mkdocs build
   ```

3. Serve locally for preview:
   ```bash
   mkdocs serve
   ```

4. Deploy to GitHub Pages:
   ```bash
   mkdocs gh-deploy --force
   ```

Alternatively, use the provided script:
```bash
./scripts/build_docs.sh
```

## Documentation URL

The documentation is published at:
https://manticoretechnologies.github.io/evrmore-authentication/

## Maintaining Documentation

When adding new features to the codebase:

1. Update the relevant documentation files
2. Add examples where appropriate
3. Include troubleshooting information for common issues
4. Rebuild and deploy the documentation

## Customization

The documentation theme and behavior are configured in `mkdocs.yml`. Key customization options include:

- Theme colors and appearance
- Navigation structure
- Plugins and extensions
- Search behavior
- Social links

## Contact Information

For questions about the documentation:
- Email: dev@manticore.technology
- GitHub: https://github.com/manticoretechnologies 