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
import com.io7m.certusine.etcd.CSEtcdOutputProvider;

/**
 * ACME client (etcd Support)
 */

module com.io7m.certusine.etcd
{
  requires static org.osgi.annotation.bundle;
  requires static org.osgi.annotation.versioning;

  requires transitive com.io7m.certusine.api;

  requires com.fasterxml.jackson.annotation;
  requires com.fasterxml.jackson.core;
  requires com.fasterxml.jackson.databind;
  requires com.io7m.dixmont.core;
  requires com.io7m.jxtrand.vanilla;
  requires java.net.http;

  provides CSCertificateOutputProviderType
    with CSEtcdOutputProvider;

  opens com.io7m.certusine.etcd.internal
    to com.io7m.jxtrand.vanilla;
  opens com.io7m.certusine.etcd.internal.dto
    to com.fasterxml.jackson.databind;

  exports com.io7m.certusine.etcd.internal
    to com.io7m.certusine.tests;
  exports com.io7m.certusine.etcd.internal.dto
    to com.io7m.certusine.tests;

  exports com.io7m.certusine.etcd;
}
