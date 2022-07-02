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
import com.io7m.claypot.core.CLPAbstractCommand;
import com.io7m.claypot.core.CLPCommandContextType;

import java.io.IOException;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Show version.
 */

@Parameters(commandDescription = "Show the package version.")
public final class CSVersion extends CLPAbstractCommand
{
  /**
   * Construct a command.
   *
   * @param inContext The command context
   */

  public CSVersion(
    final CLPCommandContextType inContext)
  {
    super(inContext);
  }

  @Override
  protected Status executeActual()
    throws IOException
  {
    try (var stream = CSVersion.class.getResourceAsStream(
      "/com/io7m/certusine/cmdline/version.txt")) {
      // CHECKSTYLE:OFF
      System.out.println(new String(stream.readAllBytes(), UTF_8));
      // CHECKSTYLE:ON
      return Status.SUCCESS;
    }
  }

  @Override
  public String name()
  {
    return "version";
  }
}
