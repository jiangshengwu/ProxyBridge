#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="4.1.0"

if [ -f "$SCRIPT_DIR/.env" ]; then
    source "$SCRIPT_DIR/.env"
fi

APP_PATH="$SCRIPT_DIR/output/ProxyBridge.app"

if [ ! -d "$APP_PATH" ]; then
    echo "Error: ProxyBridge.app not found in output directory"
    echo "Export the app from Xcode to output/ first"
    exit 1
fi

verify_universal() {
    local binary="$1"
    local archs
    archs="$(lipo -archs "$binary" 2>/dev/null || echo "")"
    if [[ "$archs" != *"arm64"* || "$archs" != *"x86_64"* ]]; then
        echo "Error: $binary is not universal (found: ${archs:-none})"
        echo "Build with ARCHS=\"arm64 x86_64\" ONLY_ACTIVE_ARCH=NO before packaging."
        exit 1
    fi
    echo "  universal ok: $binary ($archs)"
}

has_entitlement() {
    local bundle="$1"
    local key="$2"
    codesign -d --entitlements :- "$bundle" 2>/dev/null \
        | plutil -extract "$key" xml1 -o - - >/dev/null 2>&1
}

ensure_installable_signatures() {
    local extension_bundle="$1"
    local app_install_key='com\.apple\.developer\.system-extension\.install'
    local network_extension_key='com\.apple\.developer\.networking\.networkextension'
    local app_group_key='com\.apple\.security\.application-groups'

    if has_entitlement "$APP_PATH" "$app_install_key" \
        && has_entitlement "$APP_PATH" "$network_extension_key" \
        && has_entitlement "$APP_PATH" "$app_group_key" \
        && has_entitlement "$extension_bundle" "$network_extension_key" \
        && has_entitlement "$extension_bundle" "$app_group_key"; then
        codesign --verify --deep --strict "$APP_PATH"
        echo "  signing ok: required entitlements are present"
        return
    fi

    if [ -n "${SIGNING_IDENTITY:-}" ]; then
        echo "Error: signed release app is missing required system extension entitlements"
        echo "Re-export it with the app and extension provisioning profiles before packaging."
        exit 1
    fi

    echo "Applying complete ad-hoc signatures for local installation..."
    codesign --force --sign - --options runtime \
        --entitlements "$SCRIPT_DIR/extension/extensionRelease.entitlements" \
        "$extension_bundle"
    codesign --force --sign - --options runtime \
        --entitlements "$SCRIPT_DIR/ProxyBridge/ProxyBridgeRelease.entitlements" \
        "$APP_PATH"
    codesign --verify --deep --strict "$APP_PATH"

    if ! has_entitlement "$APP_PATH" "$app_install_key"; then
        echo "Error: ad-hoc signing did not embed the system extension install entitlement"
        exit 1
    fi
    echo "  signing ok: ad-hoc bundle includes required entitlements"
}

verify_universal "$APP_PATH/Contents/MacOS/ProxyBridge"
EXT_BIN="$APP_PATH/Contents/Library/SystemExtensions/com.interceptsuite.ProxyBridge.extension.systemextension/Contents/MacOS/com.interceptsuite.ProxyBridge.extension"
if [ -f "$EXT_BIN" ]; then
    verify_universal "$EXT_BIN"
fi

EXT_BUNDLE="$APP_PATH/Contents/Library/SystemExtensions/com.interceptsuite.ProxyBridge.extension.systemextension"
if [ -d "$EXT_BUNDLE" ]; then
    ensure_installable_signatures "$EXT_BUNDLE"
fi

mkdir -p "$SCRIPT_DIR/build/component"

cp -R "$APP_PATH" "$SCRIPT_DIR/build/component/"

# strip AppleDouble junk so it never lands in the payload
dot_clean "$SCRIPT_DIR/build/component" 2>/dev/null || true
find "$SCRIPT_DIR/build/component" -name '._*' -delete 2>/dev/null || true

echo "Creating installer package..."

# force BundleIsRelocatable=false so the app always installs to /Applications.
# otherwise macOS relocates the install onto any existing copy of the app it
# finds on disk (bundle relocation), leaving /Applications empty.
pkgbuild --analyze --root build/component build/component.plist
/usr/libexec/PlistBuddy -c "Set :0:BundleIsRelocatable false" build/component.plist

pkgbuild \
    --root build/component \
    --component-plist build/component.plist \
    --identifier com.interceptsuite.ProxyBridge \
    --version "$VERSION" \
    --install-location /Applications \
    build/temp.pkg

cat > build/distribution.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
    <title>ProxyBridge</title>
    <pkg-ref id="com.interceptsuite.ProxyBridge"/>
    <options customize="never" require-scripts="false"/>
    <choices-outline>
        <line choice="default">
            <line choice="com.interceptsuite.ProxyBridge"/>
        </line>
    </choices-outline>
    <choice id="default"/>
    <choice id="com.interceptsuite.ProxyBridge" visible="false">
        <pkg-ref id="com.interceptsuite.ProxyBridge"/>
    </choice>
    <pkg-ref id="com.interceptsuite.ProxyBridge" version="4.1.0" onConclusion="none">temp.pkg</pkg-ref>
</installer-gui-script>
EOF

productbuild \
    --distribution build/distribution.xml \
    --package-path build \
    output/ProxyBridge-v$VERSION-Universal-Installer.pkg

echo "Package created: output/ProxyBridge-v$VERSION-Universal-Installer.pkg"

if [ -n "$APPLE_ID" ] && [ -n "$APPLE_APP_PASSWORD" ] && [ -n "$SIGNING_IDENTITY" ]; then
    echo "Signing installer..."
    productsign --sign "$SIGNING_IDENTITY" \
        output/ProxyBridge-v$VERSION-Universal-Installer.pkg \
        output/ProxyBridge-v$VERSION-Universal-Installer-signed.pkg

    mv output/ProxyBridge-v$VERSION-Universal-Installer-signed.pkg output/ProxyBridge-v$VERSION-Universal-Installer.pkg

    echo "Notarizing installer..."
    xcrun notarytool submit output/ProxyBridge-v$VERSION-Universal-Installer.pkg \
        --apple-id "$APPLE_ID" \
        --team-id "$TEAM_ID" \
        --password "$APPLE_APP_PASSWORD" \
        --wait

    echo "Stapling notarization ticket..."
    xcrun stapler staple output/ProxyBridge-v$VERSION-Universal-Installer.pkg
    echo "Installer signed and notarized"
else
    echo "Skipping signing/notarization - set APPLE_ID, APPLE_APP_PASSWORD, SIGNING_IDENTITY, and TEAM_ID in .env"
fi

rm -rf build

echo "✓ Build complete"
echo "  App: output/ProxyBridge.app"
echo "  PKG: output/ProxyBridge-v$VERSION-Universal-Installer.pkg"
