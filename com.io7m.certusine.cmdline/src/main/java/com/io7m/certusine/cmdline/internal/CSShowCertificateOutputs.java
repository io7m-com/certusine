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


package com.io7m.certusine.cmdline.internal;

import com.beust.jcommander.Parameters;
import com.io7m.certusine.api.CSCertificateOutputProviderType;
import com.io7m.claypot.core.CLPAbstractCommand;
import com.io7m.claypot.core.CLPCommandContextType;

import java.util.ServiceLoader;

import static com.io7m.claypot.core.CLPCommandType.Status.SUCCESS;

/**
 * Show supported certificate outputs.
 */

@Parameters(commandDescription = "Show supported certificate outputs.")
public final class CSShowCertificateOutputs extends CLPAbstractCommand
{
  /**
   * Construct a command.
   *
   * @param inContext The command context
   */

  public CSShowCertificateOutputs(
    final CLPCommandContextType inContext)
  {
    super(inContext);
  }

  @Override
  protected Status executeActual()
  {
    final var iter =
      ServiceLoader.load(CSCertificateOutputProviderType.class)
        .iterator();

    while (iter.hasNext()) {
      final var dns = iter.next();
      System.out.printf("%s : %s%n", dns.name(), dns.description());
    }

    return SUCCESS;
  }

  @Override
  public String name()
  {
    return "show-certificate-outputs";
  }
}
