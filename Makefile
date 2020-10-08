build:
	go build -o bin/scanner main.go

test:
	go test -v ./...