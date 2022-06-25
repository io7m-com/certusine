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
import com.io7m.certusine.certstore.api.CSCertificateStoreFactoryType;
import com.io7m.certusine.vanilla.CSConfigurationParsers;
import com.io7m.certusine.vanilla.CSDomains;
import com.io7m.claypot.core.CLPAbstractCommand;
import com.io7m.claypot.core.CLPCommandContextType;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ServiceLoader;

import static com.io7m.claypot.core.CLPCommandType.Status.FAILURE;
import static com.io7m.claypot.core.CLPCommandType.Status.SUCCESS;

/**
 * Renew certificates.
 */

@Parameters(commandDescription = "Renew certificates.")
public final class CSRenew extends CLPAbstractCommand
{
  @Parameter(
    names = "--file",
    description = "The configuration file",
    required = true
  )
  private Path file;

  @Parameter(
    names = "--only-once",
    arity = 1,
    description = "Renew certificates once and then exit.",
    required = false
  )
  private boolean onlyOnce;

  @Parameter(
    names = "--schedule",
    description = "Renew certificates repeatedly, waiting this duration between attempts.",
    required = false,
    converter = CSDurationConverter.class
  )
  private Duration schedule = Duration.ofHours(1L);

  /**
   * Construct a command.
   *
   * @param inContext The command context
   */

  public CSRenew(
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

    final var logger = this.logger();

    while (true) {
      try {
        final var baseDirectory =
          this.file.toAbsolutePath()
            .getParent();
        final var configuration =
          parsers.parseFileWithContext(baseDirectory, this.file);

        logger.debug(
          "loaded {} domains",
          Integer.valueOf(configuration.domains().size())
        );

        final var storeFactory =
          ServiceLoader.load(CSCertificateStoreFactoryType.class)
            .findFirst()
            .orElseThrow(() -> {
              return new IllegalStateException(
                "No services available of type %s"
                  .formatted(CSCertificateStoreFactoryType.class)
              );
            });

        final var storePath =
          configuration.options().certificateStore();

        var result = SUCCESS;
        try (var store = storeFactory.open(storePath)) {
          for (final var domain : configuration.domains().values()) {
            try {
              CSDomains.renew(
                configuration.options(),
                domain,
                Clock.systemUTC(),
                store
              );
            } catch (final Exception e) {
              logger.error("error executing domain: ", e);
              result = FAILURE;
            }
          }
        }

        if (this.onlyOnce) {
          return result;
        }

        final var timeNow =
          OffsetDateTime.now(Clock.systemUTC());
        final var timeNext =
          timeNow.plus(this.schedule);
        final var timeNextClamp =
          timeNext.withNano(0);

        logger.info(
          "waiting until {} for the next renewal attempt ({})",
          timeNextClamp,
          this.schedule
        );
        Thread.sleep(this.schedule.toMillis());

      } catch (final InterruptedException e) {
        Thread.currentThread().interrupt();
      } catch (final IOException e) {
        logger.error("i/o error: {}", e.getMessage());
        if (this.onlyOnce) {
          return FAILURE;
        }
      } catch (final ParseException e) {
        CSParseErrorLogging.logParseErrors(logger, this.file, e);
        if (this.onlyOnce) {
          return FAILURE;
        }
      }
    }
  }

  @Override
  public String name()
  {
    return "renew";
  }
}
