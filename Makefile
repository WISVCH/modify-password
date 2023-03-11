.PHONY: all build run

all: build run

build:
	@docker build --pull -t ghcr.io/wisvch/modify-password:dev .

run:
	@docker run --rm -it -p 127.0.0.1:8080:8080 ghcr.io/wisvch/modify-password:dev .
