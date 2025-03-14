# Release Process

This document outlines the release process for the Evrmore Authentication system. It is intended for maintainers and contributors who are involved in preparing and publishing releases.

## Version Numbering

The Evrmore Authentication system follows [Semantic Versioning](https://semver.org/) (SemVer):

- **MAJOR** version for incompatible API changes
- **MINOR** version for new functionality in a backward-compatible manner
- **PATCH** version for backward-compatible bug fixes

Example: `1.2.3` represents major version 1, minor version 2, and patch version 3.

## Release Cycle

The project follows a time-based release cycle with the following targets:

- **Major releases**: Approximately once per year
- **Minor releases**: Every 1-3 months
- **Patch releases**: As needed for bug fixes and security updates

## Release Preparation

### 1. Create a Release Branch

For minor and major releases, create a release branch from the `main` branch:

```bash
git checkout main
git pull
git checkout -b release/vX.Y.0
```

For patch releases, create a release branch from the previous release tag:

```bash
git checkout vX.Y.0
git checkout -b release/vX.Y.Z
```

### 2. Update Version Numbers

Update the version number in the following files:

- `setup.py`
- `evrmore_authentication/__init__.py`
- `docs/index.md`

### 3. Update Changelog

Update the `CHANGELOG.md` file with the changes since the last release:

- New features
- Bug fixes
- Performance improvements
- Security updates
- Breaking changes (if any)
- Deprecations (if any)

Use the following format:

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added
- New feature 1
- New feature 2

### Changed
- Change 1
- Change 2

### Fixed
- Bug fix 1
- Bug fix 2

### Security
- Security fix 1
- Security fix 2
```

### 4. Update Documentation

Ensure that the documentation is up-to-date:

- Update API references for any new or changed functionality
- Update user guides for any changes in behavior
- Update examples to reflect the latest API
- Build and verify the documentation:
  ```bash
  mkdocs build
  ```

### 5. Run Tests

Run the full test suite to ensure everything is working correctly:

```bash
python3 -m pytest
```

### 6. Create a Pull Request

Create a pull request from the release branch to the `main` branch. The pull request should include:

- Version number updates
- Changelog updates
- Documentation updates
- Any last-minute bug fixes

Request reviews from other maintainers.

## Release Process

### 1. Merge the Release Pull Request

Once the pull request has been approved, merge it into the `main` branch.

### 2. Create a Release Tag

Create a tag for the release:

```bash
git checkout main
git pull
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

### 3. Create a GitHub Release

Create a new release on GitHub:

1. Go to the [Releases page](https://github.com/manticoretechnologies/evrmore-authentication/releases)
2. Click "Draft a new release"
3. Select the tag you just created
4. Set the title to "Evrmore Authentication vX.Y.Z"
5. Copy the relevant section from the changelog into the description
6. If it's a pre-release, check the "This is a pre-release" box
7. Click "Publish release"

### 4. Build and Publish to PyPI

Build the distribution packages:

```bash
python3 -m pip install --upgrade build
python3 -m build
```

Upload the packages to PyPI:

```bash
python3 -m pip install --upgrade twine
python3 -m twine upload dist/*
```

### 5. Update Documentation

Build and deploy the documentation:

```bash
mkdocs gh-deploy
```

### 6. Announce the Release

Announce the release on:

- GitHub Discussions
- Project website
- Social media channels
- Relevant community forums

## Post-Release

### 1. Update Development Version

After the release, update the version number in the `main` branch to the next development version:

```bash
git checkout main
```

Update the version number in:

- `setup.py`
- `evrmore_authentication/__init__.py`

Add `.dev0` to the version number to indicate that it's a development version:

```python
__version__ = "X.Y+1.0.dev0"  # For a minor release
__version__ = "X+1.0.0.dev0"  # For a major release
```

Commit and push the changes:

```bash
git add .
git commit -m "Bump version to X.Y+1.0.dev0"
git push origin main
```

### 2. Close Milestone

If you're using GitHub milestones to track progress, close the milestone for the released version and create a new one for the next version.

## Hotfix Process

For critical bug fixes that need to be released outside the normal release cycle:

1. Create a hotfix branch from the latest release tag:
   ```bash
   git checkout vX.Y.Z
   git checkout -b hotfix/issue-description
   ```

2. Fix the issue and commit the changes.

3. Update the version number and changelog.

4. Create a pull request to the `main` branch.

5. After merging, follow the normal release process for a patch release.

## Release Checklist

Use this checklist to ensure you've completed all the necessary steps:

- [ ] Create release branch
- [ ] Update version numbers
- [ ] Update changelog
- [ ] Update documentation
- [ ] Run tests
- [ ] Create pull request
- [ ] Merge pull request
- [ ] Create release tag
- [ ] Create GitHub release
- [ ] Build and publish to PyPI
- [ ] Deploy documentation
- [ ] Announce the release
- [ ] Update development version
- [ ] Close milestone

## Additional Resources

- [Semantic Versioning](https://semver.org/)
- [Python Packaging User Guide](https://packaging.python.org/guides/distributing-packages-using-setuptools/)
- [Twine Documentation](https://twine.readthedocs.io/en/latest/)
- [MkDocs Documentation](https://www.mkdocs.org/) 