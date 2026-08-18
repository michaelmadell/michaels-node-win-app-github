#!/bin/bash
set -e 

echo "Building CoreStationHXAgent (Linux) ..."

cargo build --release

echo "Generating .deb package ..."

cargo deb

echo "Generating .rpm package ..."

strip -s target/release/corestationhxagent

cargo generate-rpm

echo "Build and packaging complete!"
echo "Packages are located in the target/debian/ and target/generate-rpm/ directories."