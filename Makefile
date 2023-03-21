.PHONY: check \
	build \
	clean \
	clippy \
	docs \
	migrate \
	fmt \
	redo \
	release \
	run \
	run-db \
	test

all: check build

build:
	cargo test && cargo build

check:
	cargo check

clean:
	cargo clean

clippy:
	cargo clippy

docs:
	cargo doc --open

fmt:
	cargo fmt

# 'diesel migration generate' to create a new one
migrate:
	diesel migration run

redo:
	diesel migration redo

release:
	cargo build --release

run: build
	RK_SIDE_QUEST_DATA_PATH=$(HOME)/rk/side-quest-data cargo run

run-db:
	cd ./runtime/db && docker-compose up

test:
	cargo test
