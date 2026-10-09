BREW     ?= $(shell brew --prefix 2>/dev/null || echo /opt/homebrew)
VERSION  ?= 0.3.2
BUILD    ?= $(shell git rev-list --count HEAD 2>/dev/null || echo 1)
SIGN_ID  ?= Apple Development
CC       := clang
CFLAGS   := -DDT_VERSION=\"$(VERSION)\" -O2 -g -std=c11 -Wall -Wextra -Wno-unused-parameter -mmacosx-version-min=26.0 -I$(BREW)/include/libusb-1.0
# libusb 靜態連結：root 常駐程式不該去載入 Homebrew 底下使用者可寫的 dylib。
LDLIBS   := $(BREW)/lib/libusb-1.0.a -framework IOKit -framework CoreFoundation -framework SystemConfiguration -framework Security -lobjc

SRC      := $(wildcard src/*.c)
OBJ      := $(SRC:src/%.c=build/%.o)
DAEMON   := build/droidtetherd

APP      := build/DroidTether.app
SWIFT    := $(wildcard app/Sources/*.swift)
LABEL    := io.github.jason5545.droidtether

all: $(DAEMON)

# 版本號寫進每個 .o；改版本時用這個標記檔強迫全部重編。
build/.version-$(VERSION): | build
	rm -f build/.version-*
	touch $@

build/%.o: src/%.c src/*.h build/.version-$(VERSION) | build
	$(CC) $(CFLAGS) -c $< -o $@

$(DAEMON): $(OBJ)
	$(CC) $(CFLAGS) $^ $(LDLIBS) -o $@

build:
	mkdir -p build

# ---------- 測試（不需要裝置） ----------

build/test_packets: tests/test_packets.c src/dhcp.c src/rndis.c src/*.h | build
	$(CC) $(CFLAGS) tests/test_packets.c src/dhcp.c src/rndis.c $(LDLIBS) -o $@

test: build/test_packets
	build/test_packets build/test_packets.pcap
	@if command -v tcpdump >/dev/null; then tcpdump -nn -vvv -r build/test_packets.pcap 2>/dev/null | grep -c "udp sum ok" | xargs -I{} sh -c 'test {} -eq 3 && echo "tcpdump: 3/3 udp checksums ok" || { echo "tcpdump: checksum mismatch"; exit 1; }'; fi

# ---------- 圖示 ----------

build/svg2png: tools/svg2png.swift | build
	swiftc -O $< -o $@

build/AppIcon.icns: assets/logo.svg build/svg2png
	rm -rf build/AppIcon.iconset && mkdir -p build/AppIcon.iconset
	for s in 16 32 128 256 512; do \
		build/svg2png assets/logo.svg build/AppIcon.iconset/icon_$${s}x$${s}.png $$s; \
		build/svg2png assets/logo.svg build/AppIcon.iconset/icon_$${s}x$${s}@2x.png $$((s*2)); \
	done
	iconutil -c icns build/AppIcon.iconset -o $@

# ---------- App ----------

app: $(APP)

$(APP): $(DAEMON) $(SWIFT) app/Info.plist app/$(LABEL).plist app/Resources/*/* build/AppIcon.icns
	rm -rf $@
	mkdir -p $@/Contents/MacOS $@/Contents/Resources $@/Contents/Library/LaunchDaemons
	swiftc -O -swift-version 5 -target arm64-apple-macos26.0 -parse-as-library $(SWIFT) -o $@/Contents/MacOS/DroidTether
	cp $(DAEMON) $@/Contents/MacOS/droidtetherd
	sed -e 's/__VERSION__/$(VERSION)/' -e 's/__BUILD__/$(BUILD)/' app/Info.plist > $@/Contents/Info.plist
	cp app/$(LABEL).plist $@/Contents/Library/LaunchDaemons/
	cp -R app/Resources/*.lproj $@/Contents/Resources/
	cp build/AppIcon.icns $@/Contents/Resources/
	codesign --force --options runtime --timestamp=none --identifier $(LABEL)d --sign "$(SIGN_ID)" $@/Contents/MacOS/droidtetherd
	codesign --force --options runtime --timestamp=none --sign "$(SIGN_ID)" $@
	codesign --verify --deep --strict $@

# 只裝到 /Applications；背景服務由 App 第一次啟動時向系統註冊。
install: $(APP)
	-osascript -e 'tell application id "io.github.jason5545.DroidTether" to quit' 2>/dev/null
	rm -rf /Applications/DroidTether.app
	ditto $(APP) /Applications/DroidTether.app

clean:
	rm -rf build

.PHONY: all app install clean test
