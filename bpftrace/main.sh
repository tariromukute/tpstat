#!/bin/bash

bpftrace net/biostacks.bt
last_pid=$!
sleep 5s
kill -KILL $last_pid