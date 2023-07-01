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

import java.net.InetSocketAddress;
import java.util.Objects;

public final class CSFakeAcmeServer implements AutoCloseable
{
  private final Server server;

  public CSFakeAcmeServer(
    final Server inServer)
  {
    this.server = Objects.requireNonNull(inServer, "server");
  }

  public static CSFakeAcmeServer create(
    final int port)
    throws Exception
  {
    final var server =
      new Server(new InetSocketAddress("localhost", port));

    final var servlets = new ServletContextHandler();
    servlets.addServlet(
      CSFakeDirectory0Servlet.class,
      "/acme/directory/0");
    servlets.addServlet(
      CSFakeNonceServlet.class,
      "/acme/new-nonce");
    servlets.addServlet(
      CSFakeNewAccountServlet.class,
      "/acme/new-acct");
    servlets.addServlet(
      CSFakeAccountServlet.class,
      "/acme/acct");
    servlets.addServlet(
      CSFakeNewOrderServlet.class,
      "/acme/new-order");
    servlets.addServlet(
      CSFakeOrderFinalizeServlet.class,
      "/acme/order-finalize/*");
    servlets.addServlet(
      CSFakeOrderServlet.class,
      "/acme/order/*");
    servlets.addServlet(
      CSFakeCertificateServlet.class,
      "/acme/certificate/*");

    server.setHandler(servlets);
    server.start();
    return new CSFakeAcmeServer(server);
  }

  @Override
  public void close()
    throws Exception
  {
    this.server.stop();
  }
}
