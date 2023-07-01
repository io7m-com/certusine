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

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

import static java.nio.charset.StandardCharsets.UTF_8;

public final class CSFakeNewOrderServlet extends HttpServlet
{
  private int orders;

  public CSFakeNewOrderServlet()
  {
    this.orders = 0;
  }

  @Override
  protected void service(
    final HttpServletRequest request,
    final HttpServletResponse response)
    throws IOException
  {
    ++this.orders;

    response.setStatus(200);
    response.setContentType("application/json");
    response.setHeader(
      "Location",
      "http://localhost:20000/acme/order/" + this.orders);

    try (var stream = response.getOutputStream()) {
      stream.write(
        String.format("""
                        {
                          "finalize": "http://localhost:20000/acme/order-finalize/%d"
                        }
                              """.trim(), Integer.valueOf(this.orders))
          .getBytes(UTF_8));
      stream.flush();
    }
  }
}
