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

import com.io7m.anethum.api.ParsingException;
import com.io7m.certusine.vanilla.CSConfigurationParsers;
import com.io7m.certusine.api.CSParseErrorLogging;
import com.io7m.quarrel.core.QCommandContextType;
import com.io7m.quarrel.core.QCommandMetadata;
import com.io7m.quarrel.core.QCommandStatus;
import com.io7m.quarrel.core.QCommandType;
import com.io7m.quarrel.core.QParameterNamed1;
import com.io7m.quarrel.core.QParameterNamedType;
import com.io7m.quarrel.core.QStringType;
import com.io7m.quarrel.ext.logback.QLogback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

/**
 * Check configuration file.
 */

public final class CSCheckConfiguration implements QCommandType
{
  private static final Logger LOG =
    LoggerFactory.getLogger(CSCheckConfiguration.class);

  private static final QParameterNamed1<Path> FILE =
    new QParameterNamed1<>(
      "--file",
      List.of(),
      new QStringType.QConstant("The configuration file"),
      Optional.empty(),
      Path.class
    );

  private final QCommandMetadata metadata;

  /**
   * Construct a command.
   */

  public CSCheckConfiguration()
  {
    this.metadata = new QCommandMetadata(
      "check-configuration",
      new QStringType.QConstant("Check configuration file."),
      Optional.empty()
    );
  }

  @Override
  public List<QParameterNamedType<?>> onListNamedParameters()
  {
    return QLogback.plusParameters(List.of(FILE));
  }

  @Override
  public QCommandStatus onExecute(
    final QCommandContextType context)
    throws Exception
  {
    QLogback.configure(context);

    final var parsers =
      new CSConfigurationParsers();

    final var file =
      context.parameterValue(FILE)
        .toAbsolutePath();

    try {
      parsers.parseFileWithContext(file.getParent(), file);
      return QCommandStatus.SUCCESS;
    } catch (final IOException e) {
      LOG.error("i/o error: {}", e.getMessage());
      return QCommandStatus.FAILURE;
    } catch (final ParsingException e) {
      CSParseErrorLogging.logParseErrors(LOG, file, e);
      return QCommandStatus.FAILURE;
    }
  }

  @Override
  public QCommandMetadata metadata()
  {
    return this.metadata;
  }
}
