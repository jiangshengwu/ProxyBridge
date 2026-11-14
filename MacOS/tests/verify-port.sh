#!/usr/bin/env bash
# Native macOS validation; does not install, activate or replace a system extension.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROJECT="$ROOT/MacOS/ProxyBridge"
if [[ "$(uname -s)" != Darwin ]]; then
    echo 'Run this script on macOS with Xcode installed.' >&2
    exit 2
fi
bash "$ROOT/MacOS/tests/logic/run.sh"
while IFS= read -r -d '' path; do
    xcrun swiftc -frontend -parse "$path"
done < <(find "$PROJECT/ProxyBridge" "$PROJECT/extension" -name '*.swift' -print0)
plutil -lint "$PROJECT/extension/Info.plist" "$PROJECT/ProxyBridge.xcodeproj/project.pbxproj"
# Release signing configuration files are developer-owned and gitignored. Supply empty
# local placeholders only when absent so Xcode can load the project for an unsigned build.
for name in Signing-Config-app.xcconfig Signing-Config-ext.xcconfig; do
    if [[ ! -e "$PROJECT/$name" ]]; then touch "$PROJECT/$name"; fi
done
xcodebuild -project "$PROJECT/ProxyBridge.xcodeproj" -scheme ProxyBridge \
    -configuration Debug -destination 'generic/platform=macOS' \
    -derivedDataPath "$PROJECT/build/PortValidation" CODE_SIGNING_ALLOWED=NO build
echo 'Logic tests, Swift parsing, plist validation and unsigned Xcode build passed.'
