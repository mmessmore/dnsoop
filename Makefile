dnsnoop: $(wildcard *.go) go.mod
	go fmt *.go
	go build -o dnsnoop

dist/dnsnoop.darwin: export GOOS = darwin
dist/dnsnoop.darwin: $(wildcard *.go) go.mod
	go build -o dist/dnsnoop.darwin

dist/dnsnoop.exe: export GOOS = windows
dist/dnsnoop.exe: $(wildcard *.go) go.mod
	go build -o dist/dnsnoop.exe

dist/dnsnoop.linux: export GOOS = linux
dist/dnsnoop.linux: $(wildcard *.go) go.mod
	# try to build and fall back to building with docker
	go build -o dist/dnsnoop.linux || \
		scripts/docker-build-linux


.PHONY: dist
dist: dist/dnsnoop.darwin dist/dnsnoop.exe dist/dnsnoop.linux


.PHONY: dist
test: $(wildcard *.go) go.mod
	go test

.PHONY: clean

clean:
	rm -f dnsnoop
