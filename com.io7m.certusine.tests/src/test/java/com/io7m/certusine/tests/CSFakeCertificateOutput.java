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

import com.io7m.certusine.api.CSCertificateOutputData;
import com.io7m.certusine.api.CSCertificateOutputType;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.Queue;

public final class CSFakeCertificateOutput implements CSCertificateOutputType
{
  private final ArrayDeque<String> requests;

  public CSFakeCertificateOutput()
  {
    this.requests = new ArrayDeque<>();
  }

  public Queue<String> requests()
  {
    return this.requests;
  }

  @Override
  public String type()
  {
    return "fake";
  }

  @Override
  public String name()
  {
    return "fake";
  }

  @Override
  public void write(final CSCertificateOutputData outputData)
    throws IOException
  {
    this.requests.add(outputData.domainName());
  }
}
