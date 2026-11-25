# Builds "USB Net.app": a Swift launcher that registers the Go proxy (usbnet) as a login agent.
#   make install     build, copy to ~/Applications and turn sharing on
#   make uninstall   turn sharing off and remove the app
#   SIGN="Apple Development: …" make install   sign with your identity (default: ad-hoc)

APP  := USB Net.app
DEST := $(HOME)/Applications
SIGN ?= -
B    := build/$(APP)/Contents

.PHONY: build app install uninstall clean

build:
	mkdir -p build
	GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o build/usbnet-arm64 .
	GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o build/usbnet-amd64 .
	lipo -create -output build/usbnet build/usbnet-arm64 build/usbnet-amd64
	swiftc -O -target arm64-apple-macos13 -o build/launcher-arm64 Launcher.swift
	swiftc -O -target x86_64-apple-macos13 -o build/launcher-x86_64 Launcher.swift
	lipo -create -output build/launcher build/launcher-arm64 build/launcher-x86_64

app: build
	rm -rf "build/$(APP)"
	mkdir -p "$(B)/MacOS" "$(B)/Resources" "$(B)/Library/LaunchAgents"
	cp Info.plist "$(B)/Info.plist"
	cp build/launcher "$(B)/MacOS/USB Net"
	cp build/usbnet "$(B)/MacOS/usbnet"
	cp agent.plist "$(B)/Library/LaunchAgents/io.github.xatuke.usbnet.plist"
	cp icon/AppIcon.icns "$(B)/Resources/AppIcon.icns"
	codesign --force --options runtime --timestamp=none --sign "$(SIGN)" "$(B)/MacOS/usbnet"
	codesign --force --options runtime --timestamp=none --sign "$(SIGN)" "build/$(APP)"

install: app
	mkdir -p "$(DEST)"
	-"$(DEST)/$(APP)/Contents/MacOS/USB Net" uninstall >/dev/null 2>&1
	sleep 2  # let launchd drop the old registration (it pins the old code signature)
	rm -rf "$(DEST)/$(APP)"
	cp -R "build/$(APP)" "$(DEST)/"
	"$(DEST)/$(APP)/Contents/MacOS/USB Net" install

uninstall:
	-"$(DEST)/$(APP)/Contents/MacOS/USB Net" uninstall
	rm -rf "$(DEST)/$(APP)"

clean:
	rm -rf build
