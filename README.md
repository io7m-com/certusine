certusine
===

[![Maven Central](https://img.shields.io/maven-central/v/com.io7m.certusine/com.io7m.certusine.svg?style=flat-square)](http://search.maven.org/#search%7Cga%7C1%7Cg%3A%22com.io7m.certusine%22)
[![Maven Central (snapshot)](https://img.shields.io/nexus/s/com.io7m.certusine/com.io7m.certusine?server=https%3A%2F%2Fs01.oss.sonatype.org&style=flat-square)](https://s01.oss.sonatype.org/content/repositories/snapshots/com/io7m/certusine/)
[![Codecov](https://img.shields.io/codecov/c/github/io7m-com/certusine.svg?style=flat-square)](https://codecov.io/gh/io7m-com/certusine)
![Java Version](https://img.shields.io/badge/21-java?label=java&color=e6c35c)

![com.io7m.certusine](./src/site/resources/certusine.jpg?raw=true)

| JVM | Platform | Status |
|-----|----------|--------|
| OpenJDK (Temurin) Current | Linux | [![Build (OpenJDK (Temurin) Current, Linux)](https://img.shields.io/github/actions/workflow/status/io7m-com/certusine/main.linux.temurin.current.yml)](https://www.github.com/io7m-com/certusine/actions?query=workflow%3Amain.linux.temurin.current)|
| OpenJDK (Temurin) LTS | Linux | [![Build (OpenJDK (Temurin) LTS, Linux)](https://img.shields.io/github/actions/workflow/status/io7m-com/certusine/main.linux.temurin.lts.yml)](https://www.github.com/io7m-com/certusine/actions?query=workflow%3Amain.linux.temurin.lts)|
| OpenJDK (Temurin) Current | Windows | [![Build (OpenJDK (Temurin) Current, Windows)](https://img.shields.io/github/actions/workflow/status/io7m-com/certusine/main.windows.temurin.current.yml)](https://www.github.com/io7m-com/certusine/actions?query=workflow%3Amain.windows.temurin.current)|
| OpenJDK (Temurin) LTS | Windows | [![Build (OpenJDK (Temurin) LTS, Windows)](https://img.shields.io/github/actions/workflow/status/io7m-com/certusine/main.windows.temurin.lts.yml)](https://www.github.com/io7m-com/certusine/actions?query=workflow%3Amain.windows.temurin.lts)|

## certusine

The `certusine` package provides an ACME client.

## Features

* Uses [acme4j](https://github.com/shred/acme4j) internally for strong RFC
  compliance.
* Exclusively uses the `DNS-01` ACME challenge type for ease of integration
  with infrastructure without having to set up insecure web servers.
* A small, easily auditable codebase with a heavy use of modularity for correctness.
* Exposes a [service provider](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/util/ServiceLoader.html)
  API for integrating with new DNS APIs.
* Exposes a [service provider](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/util/ServiceLoader.html)
  API for implementing new types of certificate outputs.
* Supports [Vultr DNS](https://www.vultr.com/pt/docs/introduction-to-vultr-dns/).
* Supports [Gandi LiveDNS](https://api.gandi.net/docs/livedns/).
* Supports writing certificates to
  [looseleaf](https://www.io7m.com/software/looseleaf/) servers.
* Heavily instrumented with [OpenTelemetry](https://www.opentelemetry.io) for
  reliable service monitoring.
* An extensive automated test suite with high coverage.
* A small footprint; the client is designed to run in tiny 16-32mb JVM heap
  configurations.
* Platform independence. No platform-dependent code is included in any form,
  and installations can largely be carried between platforms without changes.
* [OSGi](https://www.osgi.org/)-ready.
* [JPMS](https://en.wikipedia.org/wiki/Java_Platform_Module_System)-ready.
* ISC license.

## Usage

See the [documentation](https://www.io7m.com/software/certusine).

