/*
 * Copyright © 2023 Mark Raynsford <code@io7m.com> https://www.io7m.com
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


open module com.io7m.certusine.tests
{
  requires com.io7m.certusine.api;
  requires com.io7m.certusine.cmdline;
  requires com.io7m.certusine.gandi;
  requires com.io7m.certusine.grafana;
  requires com.io7m.certusine.looseleaf;
  requires com.io7m.certusine.vanilla;
  requires com.io7m.certusine.vultr;

  requires org.junit.jupiter.api;
  requires org.junit.jupiter.engine;
  requires org.junit.platform.commons;
  requires org.junit.platform.engine;
  requires org.junit.platform.launcher;

  requires ch.qos.logback.classic;
  requires com.fasterxml.jackson.databind;
  requires com.io7m.looseleaf.security;
  requires com.io7m.looseleaf.server.api;
  requires com.io7m.looseleaf.server;
  requires com.io7m.quixote.core;
  requires java.net.http;
  requires jetty.servlet.api;
  requires net.bytebuddy.agent;
  requires net.bytebuddy;
  requires org.eclipse.jetty.server;
  requires org.eclipse.jetty.servlet;
  requires org.mockito;
  requires org.shredzone.acme4j;
  requires org.slf4j;

  exports com.io7m.certusine.tests;
}
