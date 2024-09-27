#!/bin/bash
dd if=/dev/urandom bs=1M count=1000 | CKEY=test go run streamCli.go e | CKEY=test go run streamCli.go d > /dev/null