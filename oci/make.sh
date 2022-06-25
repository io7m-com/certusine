#!/bin/sh -ex

rm -rf target

mkdir -p target

cp Containerfile target

rsync -av ../com.io7m.certusine.cmdline/target/certusine-distribution/ target/

podman build -t docker.io/io7m/certusine:0.0.1 target
