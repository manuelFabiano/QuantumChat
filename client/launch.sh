#!/bin/bash

for i in $(seq $1); do
  python3 main.py &
done
