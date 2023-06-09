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

import com.io7m.anethum.common.ParseException;
import com.io7m.certusine.api.CSConfiguration;
import com.io7m.certusine.certstore.api.CSCertificateStoreFactoryType;
import com.io7m.certusine.vanilla.CSConfigurationParsers;
import com.io7m.certusine.vanilla.CSDomains;
import com.io7m.certusine.vanilla.CSServices;
import com.io7m.certusine.vanilla.CSTelemetryServices;
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
import java.time.Clock;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import static com.io7m.certusine.cmdline.internal.CSParseErrorLogging.logParseErrors;
import static java.lang.Boolean.FALSE;

/**
 * Renew certificates.
 */

public final class CSRenew implements QCommandType
{
  private static final Logger LOG =
    LoggerFactory.getLogger(CSRenew.class);

  private static final QParameterNamed1<Path> FILE =
    new QParameterNamed1<>(
      "--file",
      List.of(),
      new QStringType.QConstant("The configuration file"),
      Optional.empty(),
      Path.class
    );

  private static final QParameterNamed1<Boolean> ONLY_ONCE =
    new QParameterNamed1<>(
      "--only-once",
      List.of(),
      new QStringType.QConstant("Renew certificates once and then exit."),
      Optional.of(FALSE),
      Boolean.class
    );

  private static final QParameterNamed1<Duration> SCHEDULE =
    new QParameterNamed1<>(
      "--schedule",
      List.of(),
      new QStringType.QConstant(
        "Renew certificates repeatedly, waiting this duration between attempts."),
      Optional.of(Duration.ofHours(1L)),
      Duration.class
    );

  private final QCommandMetadata metadata;

  /**
   * Construct a command.
   */

  public CSRenew()
  {
    this.metadata = new QCommandMetadata(
      "renew",
      new QStringType.QConstant("Renew certificates."),
      Optional.empty()
    );
  }

  @Override
  public List<QParameterNamedType<?>> onListNamedParameters()
  {
    return QLogback.plusParameters(List.of(FILE, SCHEDULE, ONLY_ONCE));
  }

  @Override
  public QCommandStatus onExecute(
    final QCommandContextType context)
    throws Exception
  {
    final var parsers =
      new CSConfigurationParsers();

    final var file =
      context.parameterValue(FILE)
        .toAbsolutePath();
    final var onlyOnce =
      context.parameterValue(ONLY_ONCE)
        .booleanValue();
    final var schedule =
      context.parameterValue(SCHEDULE);

    final var configurationInitial =
      CSRenew.loadConfiguration(file, parsers);

    final var telemetry =
      CSTelemetryServices.createOptional(
        configurationInitial.options()
          .openTelemetry()
      );
    final var services =
      CSServices.create(Locale.ROOT, telemetry);

    while (true) {
      try {
        final var configuration =
          CSRenew.loadConfiguration(file, parsers);

        LOG.debug(
          "loaded {} domains",
          Integer.valueOf(configuration.domains().size())
        );

        final var storeFactory =
          services.requireService(CSCertificateStoreFactoryType.class);

        final var storePath =
          configuration.options().certificateStore();

        var result = QCommandStatus.SUCCESS;
        try (var store = storeFactory.open(storePath)) {
          for (final var domain : configuration.domains().values()) {
            try {
              CSDomains.renew(
                services,
                configuration.options(),
                domain,
                Clock.systemUTC(),
                store
              );
            } catch (final Exception e) {
              LOG.error("error executing domain: ", e);
              result = QCommandStatus.FAILURE;
            }
          }
        }

        if (onlyOnce) {
          return result;
        }

        final var timeNow =
          OffsetDateTime.now(Clock.systemUTC());
        final var timeNext =
          timeNow.plus(schedule);
        final var timeNextClamp =
          timeNext.withNano(0);

        LOG.info(
          "waiting until {} for the next renewal attempt ({})",
          timeNextClamp,
          schedule
        );
        Thread.sleep(schedule.toMillis());

      } catch (final InterruptedException e) {
        Thread.currentThread().interrupt();
      } catch (final IOException e) {
        LOG.error("i/o error: {}", e.getMessage());
        if (onlyOnce) {
          return QCommandStatus.FAILURE;
        }
        pauseOnError();
      } catch (final ParseException e) {
        logParseErrors(LOG, file, e);
        if (onlyOnce) {
          return QCommandStatus.FAILURE;
        }
        pauseOnError();
      }
    }
  }

  private static CSConfiguration loadConfiguration(
    final Path file,
    final CSConfigurationParsers parsers)
    throws IOException, ParseException
  {
    final var baseDirectory = file.toAbsolutePath().getParent();
    return parsers.parseFileWithContext(baseDirectory, file);
  }

  private static void pauseOnError()
  {
    try {
      Thread.sleep(3_000L);
    } catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }


  @Override
  public QCommandMetadata metadata()
  {
    return this.metadata;
  }
}
