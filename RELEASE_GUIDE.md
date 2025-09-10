# RAVN Release Management Guide

## 🚀 Release System Overview

RAVN includes a comprehensive release management system that automates the creation, packaging, and distribution of releases. The system supports both local releases and automated GitHub releases.

## 📋 Release Types

### 1. Local Release
Creates release artifacts locally without pushing to GitHub.

### 2. Git Tag Release
Creates a git tag for the current version.

### 3. GitHub Release
Triggers automated GitHub release with full packaging.

### 4. Full Release
Complete release process: local + tag + GitHub.

## 🛠️ Release Commands

### Makefile Targets

```bash
# Create local release
make release-local

# Create git tag
make release-tag

# Trigger GitHub release
make release-github

# Full release process
make release-full

# List existing releases
make release-list
```

### Direct Script Usage

```bash
# Create local release
./scripts/release.sh local [version] [notes]

# Create git tag
./scripts/release.sh tag [version] [notes]

# Trigger GitHub release
./scripts/release.sh github [version]

# Full release process
./scripts/release.sh full [version] [notes]

# List releases
./scripts/release.sh list
```

## 🎯 Release Workflow

### 1. Prepare for Release

```bash
# Update version (if needed)
make version-update

# Check current version
make version

# Ensure clean working tree
git status
```

### 2. Create Release

#### Option A: Full Automated Release
```bash
# Complete release process
make release-full
```

#### Option B: Step-by-Step Release
```bash
# 1. Create local release
make release-local

# 2. Create git tag
make release-tag

# 3. Trigger GitHub release
make release-github
```

### 3. Verify Release

```bash
# List all releases
make release-list

# Check GitHub releases
gh release list
```

## 📦 Release Artifacts

Each release includes:

### Binary Files
- `ravn-{VERSION}-linux-x86_64` - Main executable
- `ravn-{VERSION}-linux-x86_64.tar.gz` - Compressed archive

### Checksums
- `ravn-{VERSION}-linux-x86_64.sha256` - SHA256 checksum
- `ravn-{VERSION}-linux-x86_64.md5` - MD5 checksum
- `ravn-{VERSION}-linux-x86_64.tar.gz.sha256` - Archive checksum

### Installation Script
- `install-ravn-{VERSION}.sh` - Automated installation script

## 🔧 GitHub Actions Integration

### Automated Release Workflow

**File**: `.github/workflows/release.yml`

**Triggers**:
- Manual workflow dispatch
- Git tag push (v*)

**Features**:
- Full compilation and testing
- Multi-format packaging
- Checksum generation
- Installation script creation
- GitHub release creation

### Manual Release Trigger

1. Go to GitHub Actions tab
2. Select "Create Release" workflow
3. Click "Run workflow"
4. Choose options:
   - Release type (patch/minor/major/current)
   - Release notes (optional)
   - Pre-release flag

## 📝 Release Notes

### Auto-Generated Notes
The system automatically generates release notes including:
- Version information
- Build date and commit SHA
- Feature highlights
- Installation instructions
- System requirements

### Custom Release Notes
You can provide custom release notes:
```bash
./scripts/release.sh full "20241215.1" "Custom release notes here"
```

### Release Template
Use the template at `.github/RELEASE_TEMPLATE.md` for consistent formatting.

## 🏷️ Version Management

### Version Format
`YYYYMMDD.MAGIC`
- **YYYYMMDD**: Date when version was created
- **MAGIC**: Incremental number for same-day builds

### Version Examples
- `20241215.1` - First build on December 15, 2024
- `20241215.2` - Second build on December 15, 2024
- `20241216.1` - First build on December 16, 2024

### Version Commands
```bash
make version          # Show current version
make version-update   # Update version (if changes detected)
make version-force    # Force version update
make version-reset    # Reset to current date.1
```

## 🔍 Release Verification

### Local Verification
```bash
# Check binary
./artifacts/ravn --version

# Verify checksums
sha256sum -c releases/v{VERSION}/ravn-{VERSION}-linux-x86_64.sha256
```

### GitHub Verification
```bash
# List releases
gh release list

# Download and test
gh release download v{VERSION}
```

## 🚨 Troubleshooting

### Common Issues

**Release fails to build**:
```bash
# Check dependencies
make clean
make all

# Verify version header
cat src/version.h
```

**Git tag already exists**:
```bash
# Delete existing tag
git tag -d v{VERSION}
git push origin :refs/tags/v{VERSION}

# Recreate tag
make release-tag
```

**GitHub release fails**:
- Check GitHub CLI authentication: `gh auth status`
- Verify repository permissions
- Check workflow logs in GitHub Actions

### Debug Commands

```bash
# Check git status
git status

# Verify version
make version

# Test build
make clean && make all

# Check release script
./scripts/release.sh help
```

## 📊 Release Statistics

### Build Information
- **Build Date**: Automatically set
- **Build Time**: UTC timestamp
- **Commit SHA**: Git commit hash
- **Binary Size**: Automatically calculated

### Performance Metrics
- **Compilation Time**: Tracked in CI
- **Binary Size**: Optimized for deployment
- **Test Coverage**: Automated validation

## 🔄 Release Automation

### Daily CI Integration
The daily CI system automatically:
- Builds and tests the project
- Updates version information
- Creates version tags
- Prepares for releases

### Scheduled Releases
Configure automatic releases:
1. Modify `.github/workflows/daily-ci.yml`
2. Add release trigger conditions
3. Set release criteria

## 📚 Best Practices

### Before Release
1. **Update version**: `make version-update`
2. **Test thoroughly**: `make all && ./artifacts/ravn --version`
3. **Check git status**: Ensure clean working tree
4. **Review changes**: Verify all modifications

### During Release
1. **Use full release**: `make release-full`
2. **Provide notes**: Include meaningful release notes
3. **Test artifacts**: Verify all files are correct
4. **Monitor process**: Watch for any errors

### After Release
1. **Verify GitHub**: Check release appears correctly
2. **Test installation**: Download and install release
3. **Update documentation**: Update any version references
4. **Announce release**: Notify users of new version

## 🎯 Release Checklist

### Pre-Release
- [ ] Version updated (`make version`)
- [ ] All tests passing (`make all`)
- [ ] Clean git working tree
- [ ] Release notes prepared
- [ ] Dependencies verified

### Release Process
- [ ] Run release command (`make release-full`)
- [ ] Verify local artifacts created
- [ ] Check git tag created
- [ ] Confirm GitHub release triggered
- [ ] Monitor workflow completion

### Post-Release
- [ ] Verify GitHub release published
- [ ] Test installation script
- [ ] Check all artifacts downloadable
- [ ] Update documentation
- [ ] Announce to users

## 🔗 Integration Examples

### CI/CD Pipeline
```yaml
# Example GitHub Actions step
- name: Create Release
  if: github.ref == 'refs/heads/main'
  run: |
    make version-update
    make release-full
```

### Automated Deployment
```bash
# Example deployment script
#!/bin/bash
VERSION=$(make version | grep "Current version" | cut -d' ' -f3)
make release-full
# Deploy to production
```

## 📞 Support

For release-related issues:
1. Check this guide
2. Review GitHub Actions logs
3. Test locally with `make release-local`
4. Create issue with release details

---

**RAVN Release System** - Professional release management with automation
