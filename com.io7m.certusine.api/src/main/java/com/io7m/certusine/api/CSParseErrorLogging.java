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


package com.io7m.certusine.api;

import com.io7m.anethum.api.ParseStatusType;
import com.io7m.anethum.api.ParsingException;
import org.slf4j.Logger;

import java.nio.file.Path;

/**
 * Functions to log parse errors.
 */

public final class CSParseErrorLogging
{
  private CSParseErrorLogging()
  {

  }

  /**
   * Log a parse error.
   *
   * @param logger The logger
   * @param file   The source file
   * @param status The status
   */

  public static void logError(
    final Logger logger,
    final Path file,
    final ParseStatusType status)
  {
    switch (status.severity()) {
      case PARSE_ERROR -> {
        logger.error(
          "{}:{}:{}: {}",
          file.getFileName(),
          Integer.valueOf(status.lexical().line()),
          Integer.valueOf(status.lexical().column()),
          status.message()
        );
      }
      case PARSE_WARNING -> {
        logger.warn(
          "{}:{}:{}: {}",
          file.getFileName(),
          Integer.valueOf(status.lexical().line()),
          Integer.valueOf(status.lexical().column()),
          status.message()
        );
      }
      case PARSE_INFO -> {
        logger.info(
          "{}:{}:{}: {}",
          file.getFileName(),
          Integer.valueOf(status.lexical().line()),
          Integer.valueOf(status.lexical().column()),
          status.message()
        );
      }
    }
  }

  /**
   * Log a parse error.
   *
   * @param logger The logger
   * @param file   The source file
   * @param e      The exception
   */

  public static void logParseErrors(
    final Logger logger,
    final Path file,
    final ParsingException e)
  {
    for (final var error : e.statusValues()) {
      logError(logger, file, error);
    }
  }
}
