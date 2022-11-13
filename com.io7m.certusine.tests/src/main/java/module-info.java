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

/**
 * ACME client (unit tests)
 */

module com.io7m.certusine.tests
{
  requires com.io7m.certusine.api;
  requires com.io7m.certusine.certstore.api;
  requires com.io7m.certusine.etcd;
  requires com.io7m.certusine.looseleaf;
  requires com.io7m.certusine.vanilla;
  requires com.io7m.certusine.vultr;

  requires com.io7m.jaffirm.core;
  requires com.io7m.looseleaf.protocol.v1;
  requires com.io7m.looseleaf.server.api;
  requires com.io7m.looseleaf.server;
  requires java.net.http;
  requires org.bouncycastle.pkix;
  requires org.eclipse.jetty.server;
  requires org.eclipse.jetty.servlet;
  requires org.shredzone.acme4j;

  exports com.io7m.certusine.tests;
}
