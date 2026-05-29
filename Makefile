BUILD_CGO_ENABLED  := 0
SERVICE_NAME       := swan-ng
REBASE_URL         := "github.com/dimaskiddo/swan-ng"
COMMIT_MSG         := "update improvement"

VERSION 					 := $(shell git describe --tags --always 2>/dev/null | sed -e 's|^v||g' || echo "dev")
COMMIT						 := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")

.PHONY:

.SILENT:

init:
	make clean
	GO111MODULE=on go mod init

init-dist:
	mkdir -p dist

vendor:
	make clean
	GO111MODULE=on go mod tidy
	GO111MODULE=on go mod vendor

release:
	make vendor
	make clean-dist
	goreleaser release --parallelism 1 --rm-dist --snapshot --skip-publish
	echo "Release '$(SERVICE_NAME)' complete, please check dist directory."

publish:
	make vendor
	make clean-dist
	GITHUB_TOKEN=$(GITHUB_TOKEN) goreleaser release --parallelism 1 --rm-dist
	echo "Publish '$(SERVICE_NAME)' complete, please check your repository releases."

build:
	make vendor
	make init-dist
	CGO_ENABLED=$(BUILD_CGO_ENABLED) go build -ldflags="-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)" -trimpath -a -o dist/$(SERVICE_NAME) ./cmd/swan-ng
	echo "Build '$(SERVICE_NAME)' complete, output: dist/$(SERVICE_NAME)"

docker-build:
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) -t dimaskiddo/swan-ng:v$(VERSION) .
	echo "Docker Build '$(SERVICE_NAME)' complete."

run:
	make vendor
	go run ./cmd/swan-ng

test:
	CGO_ENABLED=$(BUILD_CGO_ENABLED) go test ./... -v -count=1

clean-dist:
	rm -rf dist

clean-build:
	rm -f dist/$(SERVICE_NAME)

clean:
	make clean-dist
	make clean-build
	rm -rf vendor

commit:
	make vendor
	make clean
	git add .
	git commit -am $(COMMIT_MSG)

rebase:
	rm -rf .git
	find . -type f -iname "*.go*" -exec sed -i '' -e "s%github.com/dimaskiddo/swan-ng%$(REBASE_URL)%g" {} \;
	git init
	git remote add origin https://$(REBASE_URL).git

push:
	git push origin master

pull:
	git pull origin master
