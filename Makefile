.PHONY: build web test e2e clean

build: web
	CGO_ENABLED=0 go build -o hauswart-server ./cmd/hauswart-server
	CGO_ENABLED=0 go build -o hauswart-agent ./cmd/hauswart-agent

web:
	cd web && npm ci --no-audit --no-fund && npm run build

test:
	go vet ./...
	go test ./...

e2e:
	python3 test/e2e.py

clean:
	rm -f hauswart-server hauswart-agent
	find web/dist -mindepth 1 ! -name .gitkeep -delete
