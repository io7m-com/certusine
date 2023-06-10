/*
 * Copyright © 2022 Mark Raynsford <code@io7m.com> https://www.io7m.com
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
 * IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

import com.io7m.certusine.api.CSCertificateOutputProviderType;
import com.io7m.certusine.api.CSDNSConfiguratorProviderType;
import com.io7m.certusine.certstore.api.CSCertificateStoreFactoryType;
import com.io7m.certusine.vanilla.CSCertificateOutputProviderDirectory;
import com.io7m.certusine.vanilla.internal.store.CSCertificateStoreH2MVFactory;

/**
 * ACME client (Vanilla implementation)
 */

module com.io7m.certusine.vanilla
{
  requires static org.osgi.annotation.bundle;
  requires static org.osgi.annotation.versioning;

  requires transitive com.io7m.anethum.api;
  requires transitive com.io7m.certusine.api;
  requires transitive com.io7m.certusine.certstore.api;

  requires com.h2database.mvstore;
  requires com.io7m.jaffirm.core;
  requires com.io7m.jdeferthrow.core;
  requires com.io7m.jxtrand.vanilla;
  requires com.io7m.repetoir.core;
  requires jakarta.xml.bind;
  requires org.bouncycastle.pkix;
  requires org.bouncycastle.provider;
  requires org.dnsjava;
  requires org.shredzone.acme4j.utils;
  requires org.shredzone.acme4j;
  requires org.slf4j;

  requires io.opentelemetry.api;
  requires io.opentelemetry.context;
  requires io.opentelemetry.exporter.otlp;
  requires io.opentelemetry.sdk.common;
  requires io.opentelemetry.sdk.logs;
  requires io.opentelemetry.sdk.metrics;
  requires io.opentelemetry.sdk.trace;
  requires io.opentelemetry.sdk;
  requires io.opentelemetry.semconv;

  exports com.io7m.certusine.vanilla;

  uses CSCertificateOutputProviderType;
  uses CSDNSConfiguratorProviderType;
  uses CSCertificateStoreFactoryType;

  provides CSCertificateOutputProviderType
    with CSCertificateOutputProviderDirectory;

  provides CSCertificateStoreFactoryType
    with CSCertificateStoreH2MVFactory;

  opens com.io7m.certusine.vanilla.internal
    to com.io7m.jxtrand.vanilla;

  opens com.io7m.certusine.vanilla.internal.jaxb
    to jakarta.xml.bind;

  exports com.io7m.certusine.vanilla.internal
    to com.io7m.certusine.tests;
  exports com.io7m.certusine.vanilla.internal.tasks
    to com.io7m.certusine.tests;
  exports com.io7m.certusine.vanilla.internal.store
    to com.io7m.certusine.tests;
  exports com.io7m.certusine.vanilla.internal.dns
    to com.io7m.certusine.tests;
  exports com.io7m.certusine.vanilla.internal.events
    to com.io7m.certusine.tests;

  opens com.io7m.certusine.vanilla to
    com.io7m.jxtrand.vanilla;
  exports com.io7m.certusine.vanilla.internal.telemetry to com.io7m.certusine.tests;
  opens com.io7m.certusine.vanilla.internal.telemetry to com.io7m.jxtrand.vanilla;
}
