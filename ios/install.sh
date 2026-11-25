#!/bin/zsh
# Build USB Net and install it on the iPhone connected by USB. Needs Xcode and xcodegen (brew install xcodegen).
set -e
cd ${0:A:h}
[[ -f Local.xcconfig ]] || { echo "Copy Local.example.xcconfig to Local.xcconfig and set your team ID first."; exit 1; }
xcodegen generate --quiet
xcodebuild -project USBNet.xcodeproj -scheme USBNet -configuration Release -destination generic/platform=iOS \
  -derivedDataPath build -allowProvisioningUpdates -allowProvisioningDeviceRegistration -quiet build
DEVICE=$(xcrun devicectl list devices 2>/dev/null | awk '/iPhone/ && /available/ {for (i=1;i<=NF;i++) if ($i ~ /^[0-9A-F-]{25,}$/) {print $i; exit}}')
[[ -n $DEVICE ]] || { echo "No iPhone found. Plug it in, unlock it and tap Trust."; exit 1; }
xcrun devicectl device install app --device $DEVICE build/Build/Products/Release-iphoneos/USBNet.app
echo "Installed USB Net on your iPhone."
