VERSION ?= 0.1.0
LDFLAGS := -X github.com/Two-Play/hauswart/internal/agent.Version=$(VERSION)

.PHONY: build web gui test test-gui e2e test-vm regression regression-fast playground packages test-packages clean

build: web
	mkdir -p dist
	CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o dist/hauswart-server ./cmd/hauswart-server
	CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o dist/hauswart-agent ./cmd/hauswart-agent
	CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o dist/hauswart-admin ./cmd/hauswart-admin

# The desktop apps link against graphics libraries, so they are built apart.
gui:
	packaging/build-gui.sh $(VERSION)

web:
	cd web && npm ci --no-audit --no-fund && npm run build

test:
	go vet ./...
	go test ./...

test-gui:
	cd gui && go vet ./admin ./tray ./agentclient ./translations && go test ./...

e2e:
	python3 test/e2e.py
	python3 test/e2e.py renewal
	python3 test/e2e.py notify

test-vm:
	python3 test/vm.py

# All suites side by side, with a table of how long each took.
regression:
	python3 test/regression.py

regression-fast:
	python3 test/regression.py --fast

# A server and a desktop VM to try Hauswart by hand. ARGS=--kde for Plasma.
playground:
	python3 test/playground.py $(ARGS)

test-packages: packages
	VERSION=$(VERSION) python3 test/packages.py

packages: build gui
	rpmbuild -bb packaging/hauswart.spec \
		--define '_topdir $(CURDIR)/dist/rpmbuild' \
		--define '_rpmdir $(CURDIR)/dist' \
		--define '_build_name_fmt %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm' \
		--define 'hw_version $(VERSION)' \
		--define 'hw_root $(CURDIR)'
	rm -rf dist/rpmbuild
	packaging/build-deb.sh server $(VERSION)
	packaging/build-deb.sh agent $(VERSION)
	packaging/build-deb.sh admin $(VERSION)
	packaging/build-deb.sh tray $(VERSION)
	packaging/build-deb.sh admin-gui $(VERSION)
	rm -rf dist/hauswart-$(VERSION)
	mkdir -p dist/hauswart-$(VERSION)
	cp dist/hauswart-server dist/hauswart-agent dist/hauswart-admin LICENSE packaging/install.sh packaging/server.env packaging/notify.env packaging/hauswart.sysusers packaging/systemd/*.service dist/hauswart-$(VERSION)/
	tar -czf dist/hauswart-$(VERSION)-linux-amd64.tar.gz -C dist hauswart-$(VERSION)
	rm -rf dist/hauswart-$(VERSION)

clean:
	rm -rf dist
	find web/dist -mindepth 1 ! -name .gitkeep -delete
