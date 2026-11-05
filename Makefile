VERSION ?= 0.1.0
LDFLAGS := -X github.com/philippe/hauswart/internal/agent.Version=$(VERSION)

.PHONY: build web test e2e packages test-packages clean

build: web
	mkdir -p dist
	CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o dist/hauswart-server ./cmd/hauswart-server
	CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o dist/hauswart-agent ./cmd/hauswart-agent

web:
	cd web && npm ci --no-audit --no-fund && npm run build

test:
	go vet ./...
	go test ./...

e2e:
	python3 test/e2e.py

test-packages: packages
	VERSION=$(VERSION) python3 test/packages.py

packages: build
	rpmbuild -bb packaging/hauswart.spec \
		--define '_topdir $(CURDIR)/dist/rpmbuild' \
		--define '_rpmdir $(CURDIR)/dist' \
		--define '_build_name_fmt %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm' \
		--define 'hw_version $(VERSION)' \
		--define 'hw_root $(CURDIR)'
	rm -rf dist/rpmbuild
	packaging/build-deb.sh server $(VERSION)
	packaging/build-deb.sh agent $(VERSION)
	rm -rf dist/hauswart-$(VERSION)
	mkdir -p dist/hauswart-$(VERSION)
	cp dist/hauswart-server dist/hauswart-agent packaging/install.sh packaging/server.env packaging/hauswart.sysusers packaging/systemd/*.service dist/hauswart-$(VERSION)/
	tar -czf dist/hauswart-$(VERSION)-linux-amd64.tar.gz -C dist hauswart-$(VERSION)
	rm -rf dist/hauswart-$(VERSION)

clean:
	rm -rf dist
	find web/dist -mindepth 1 ! -name .gitkeep -delete
