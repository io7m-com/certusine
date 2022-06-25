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


package com.io7m.certusine.tests;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

import java.net.InetSocketAddress;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

public final class CSFakeVultrServer implements AutoCloseable
{
  private final Server server;
  private final ServletContextHandler servlets;

  public CSFakeVultrServer(
    final Server inServer,
    final ServletContextHandler inServlets)
  {
    this.server =
      Objects.requireNonNull(inServer, "server");
    this.servlets =
      Objects.requireNonNull(inServlets, "servlets");
  }

  public static CSFakeVultrServer create(
    final int port)
    throws Exception
  {
    final var server =
      new Server(new InetSocketAddress("localhost", port));

    final var servlets = new ServletContextHandler();
    servlets.addServlet(CSFakeVultrDNSServlet.class, "/domains/*");

    server.setHandler(servlets);
    server.start();
    return new CSFakeVultrServer(server, servlets);
  }

  @Override
  public void close()
    throws Exception
  {
    this.server.stop();
  }

  public void setResponseCode(
    final int code)
  {
    CSFakeVultrDNSServlet.responseCode = code;
  }
}
