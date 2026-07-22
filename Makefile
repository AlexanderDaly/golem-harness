.PHONY: proto lint-proto

proto:
	buf dep update
	buf generate

lint-proto:
	buf lint
