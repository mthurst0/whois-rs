.PHONY: check \
	build \
	clean \
	docs \
	fmt \
	lint \
	migrate \
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

docs:
	cargo doc --open

fmt:
	cargo fmt

lint:
	cargo clippy

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
