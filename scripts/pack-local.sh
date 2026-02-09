#!/bin/bash
#
# RASP.Net Local Package Builder
# Builds and packs RASP NuGet packages locally for development.
# Works on Linux and macOS.
#
# Usage:
#   ./pack-local.sh [Configuration] [Version]
#   ./pack-local.sh Release 1.0.0-local
#

set -e

CONFIGURATION="${1:-Release}"
VERSION="${2:-1.0.0-local}"

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
SRC_DIR="$REPO_ROOT/src"
LOCAL_PACKAGES_DIR="$REPO_ROOT/local-packages"
NUGET_CONFIG_PATH="$REPO_ROOT/modules/nuget.config"

echo "===================================="
echo " RASP.Net Local Package Builder"
echo "===================================="
echo ""
echo "Configuration: $CONFIGURATION"
echo "Version: $VERSION"
echo "Output: $LOCAL_PACKAGES_DIR"
echo ""

# Create local packages directory
mkdir -p "$LOCAL_PACKAGES_DIR"
echo "[+] Created local-packages directory"

# Clean old packages
rm -f "$LOCAL_PACKAGES_DIR"/*.nupkg 2>/dev/null || true
echo "[+] Cleaned old packages"

# Projects to pack (in dependency order)
PROJECTS=(
    "Rasp.Core"
    "Rasp.SourceGenerators"
    "Rasp.Instrumentation.Grpc"
    "Rasp.Instrumentation.AspNetCore"
    "Rasp.Bootstrapper"
)

# Build and pack each project
for project in "${PROJECTS[@]}"; do
    PROJECT_PATH="$SRC_DIR/$project/$project.csproj"
    
    if [ ! -f "$PROJECT_PATH" ]; then
        echo "[!] Project not found: $PROJECT_PATH"
        continue
    fi
    
    echo ""
    echo "[*] Packing $project..."
    
    # Restore first
    dotnet restore "$PROJECT_PATH" --verbosity quiet
    
    # Then pack
    if dotnet pack "$PROJECT_PATH" \
        -c "$CONFIGURATION" \
        -o "$LOCAL_PACKAGES_DIR" \
        -p:Version="$VERSION" \
        -p:PackageVersion="$VERSION" \
        --no-restore 2>/dev/null; then
        echo "[+] Packed $project successfully"
    else
        echo "[!] Failed with --no-restore, trying with restore..."
        if dotnet pack "$PROJECT_PATH" \
            -c "$CONFIGURATION" \
            -o "$LOCAL_PACKAGES_DIR" \
            -p:Version="$VERSION" \
            -p:PackageVersion="$VERSION"; then
            echo "[+] Packed $project successfully"
        else
            echo "[X] Failed to pack $project"
            exit 1
        fi
    fi
done

# Create nuget.config for modules if not exists
if [ ! -f "$NUGET_CONFIG_PATH" ]; then
    cat > "$NUGET_CONFIG_PATH" << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
    <add key="rasp-local" value="../local-packages" />
  </packageSources>
  <packageSourceMapping>
    <packageSource key="nuget.org">
      <package pattern="*" />
    </packageSource>
    <packageSource key="rasp-local">
      <package pattern="Rasp.*" />
    </packageSource>
  </packageSourceMapping>
</configuration>
EOF
    echo ""
    echo "[+] Created nuget.config in modules/"
else
    echo ""
    echo "[i] nuget.config already exists in modules/"
fi

TARGET_PROJ="$REPO_ROOT/modules/dotnet-grpc-library-api/LibrarySystem.Grpc/LibrarySystem.Grpc.csproj"

if [ -f "$TARGET_PROJ" ]; then
    echo ""
    echo "[*] Auto-Injecting into Victim App..."
    
    # 1. Remove old references
    dotnet remove "$TARGET_PROJ" reference "$SRC_DIR/Rasp.Instrumentation.Grpc/Rasp.Instrumentation.Grpc.csproj" 2>/dev/null || true
    dotnet remove "$TARGET_PROJ" reference "$SRC_DIR/Rasp.SourceGenerators/Rasp.SourceGenerators.csproj" 2>/dev/null || true

    # 2. Add package reference
    dotnet add "$TARGET_PROJ" package "Rasp.Instrumentation.Grpc" --version "$VERSION" --source "$LOCAL_PACKAGES_DIR"
    dotnet add "$TARGET_PROJ" package "Rasp.Bootstrapper" --version "$VERSION" --source "$LOCAL_PACKAGES_DIR"

    echo "[+] Dependencies injected successfully"
else
    echo "[!] Victim app not found at $TARGET_PROJ (Skipping injection)"
fi

echo ""
echo "===================================="
echo " Build Complete!"
echo "===================================="
echo ""
echo "Packages created in: $LOCAL_PACKAGES_DIR"
echo ""
echo "To use in your project, update your .csproj:"
echo ""
echo "  <PackageReference Include=\"Rasp.Instrumentation.Grpc\" Version=\"$VERSION\" />"
echo "  <PackageReference Include=\"Rasp.Bootstrapper\" Version=\"$VERSION\" />"
echo ""
echo "Then run: dotnet restore"
echo ""

# List created packages
echo "Created packages:"
ls -1 "$LOCAL_PACKAGES_DIR"/*.nupkg 2>/dev/null | while read -r pkg; do
    echo "  - $(basename "$pkg")"
done
