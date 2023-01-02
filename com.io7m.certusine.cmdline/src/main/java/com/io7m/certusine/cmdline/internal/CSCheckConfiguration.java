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

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import com.io7m.anethum.common.ParseException;
import com.io7m.certusine.vanilla.CSConfigurationParsers;
import com.io7m.claypot.core.CLPAbstractCommand;
import com.io7m.claypot.core.CLPCommandContextType;

import java.io.IOException;
import java.nio.file.Path;

import static com.io7m.claypot.core.CLPCommandType.Status.FAILURE;
import static com.io7m.claypot.core.CLPCommandType.Status.SUCCESS;

/**
 * Check configuration file.
 */

@Parameters(commandDescription = "Check configuration file.")
public final class CSCheckConfiguration extends CLPAbstractCommand
{
  @Parameter(
    names = "--file",
    description = "The configuration file",
    required = true
  )
  private Path file;

  /**
   * Construct a command.
   *
   * @param inContext The command context
   */

  public CSCheckConfiguration(
    final CLPCommandContextType inContext)
  {
    super(inContext);
  }

  @Override
  protected Status executeActual()
    throws Exception
  {
    final var parsers =
      new CSConfigurationParsers();

    this.file =
      this.file.toAbsolutePath();

    final var logger = this.logger();
    try {
      parsers.parseFileWithContext(this.file.getParent(), this.file);
      return SUCCESS;
    } catch (final IOException e) {
      logger.error("i/o error: {}", e.getMessage());
      return FAILURE;
    } catch (final ParseException e) {
      CSParseErrorLogging.logParseErrors(logger, this.file, e);
      return FAILURE;
    }
  }

  @Override
  public String name()
  {
    return "check-configuration";
  }
}
