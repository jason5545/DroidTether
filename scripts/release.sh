#!/bin/bash
# 發版：Xcode 雲端 Developer ID 簽章 → Apple 公證 → DMG / ZIP。
# 用 Xcode 設定裡已登入的開發者帳號（-allowProvisioningUpdates），不需要本機的 Developer ID 憑證或公證密碼。
#   scripts/release.sh 0.3.4
set -euo pipefail
VERSION="${1:?usage: scripts/release.sh <version>}"
cd "$(dirname "$0")/.."
OUT=build/release
TEAM=$(awk '/DEVELOPMENT_TEAM:/{print $2; exit}' project.yml)
BUILD=$(git rev-list --count HEAD)
ARCHIVE="$OUT/Tetherline.xcarchive"

rm -rf "$OUT" && mkdir -p "$OUT"
make test
make build/AppIcon.icns
xcodegen generate --quiet

echo "==> archive $VERSION ($BUILD)"
xcodebuild archive -quiet -project Tetherline.xcodeproj -scheme Tetherline -configuration Release \
    -archivePath "$ARCHIVE" -derivedDataPath build/xcode \
    MARKETING_VERSION="$VERSION" CURRENT_PROJECT_VERSION="$BUILD" -allowProvisioningUpdates

cat > "$OUT/ExportOptions.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>method</key><string>developer-id</string>
    <key>signingStyle</key><string>automatic</string>
    <key>teamID</key><string>$TEAM</string>
    <key>destination</key><string>upload</string>
</dict>
</plist>
PLIST

echo "==> sign with Developer ID and upload for notarization"
xcodebuild -exportArchive -archivePath "$ARCHIVE" -exportOptionsPlist "$OUT/ExportOptions.plist" \
    -exportPath "$OUT/upload" -allowProvisioningUpdates

echo "==> waiting for notarization"
for i in $(seq 1 60); do
    if xcodebuild -exportNotarizedApp -archivePath "$ARCHIVE" -exportPath "$OUT/notarized" >"$OUT/notarized.log" 2>&1; then
        break
    fi
    [ "$i" = 60 ] && { cat "$OUT/notarized.log"; echo "notarization did not finish in 30 minutes"; exit 1; }
    sleep 30
done

APP="$OUT/notarized/Tetherline.app"
codesign --verify --deep --strict "$APP"
xcrun stapler validate "$APP"
spctl -a -vv -t exec "$APP"

make package APP_SRC="$APP" VERSION="$VERSION"

# 清掉建置過程留下的 App 副本，並從 LaunchServices 取消登記。
# 同一個 bundle ID 在系統裡登記好幾份時，背景服務的程式路徑可能被解析到錯的副本。
LSREGISTER=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister
find "$PWD/build" \( -name "Tetherline.app" -o -name "DroidTether.app" \) -type d -prune 2>/dev/null | while read -r app; do
    "$LSREGISTER" -u "$app" 2>/dev/null || true
done
rm -rf build/xcode "$ARCHIVE" "$OUT/notarized" "$OUT/upload"
echo "==> done: build/dist/Tetherline-$VERSION.dmg"
