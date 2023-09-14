# [Choice] Debian OS version (use bullseye on local arm64/Apple Silicon): buster, bullseye
ARG VARIANT="bullseye"
FROM rust:1-${VARIANT}

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
	# Remove imagemagick due to https://security-tracker.debian.org/tracker/CVE-2019-10131
	&& apt-get purge -y imagemagick imagemagick-6-common

# Tools
RUN apt-get -y install --no-install-recommends vim git

# Rustfmt with nightly toolchain
RUN rustup install nightly
RUN rustup component add rustfmt --toolchain nightly
RUN rustup component add clippy --toolchain nightly

# Dependencies
