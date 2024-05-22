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

import com.io7m.certusine.api.CSCertificateName;
import com.io7m.certusine.looseleaf.CSLLCredentials;
import com.io7m.certusine.looseleaf.CSLLDownloader;
import com.io7m.quarrel.core.QCommandContextType;
import com.io7m.quarrel.core.QCommandMetadata;
import com.io7m.quarrel.core.QCommandStatus;
import com.io7m.quarrel.core.QCommandType;
import com.io7m.quarrel.core.QParameterNamed0N;
import com.io7m.quarrel.core.QParameterNamed1;
import com.io7m.quarrel.core.QParameterNamedType;
import com.io7m.quarrel.core.QStringType.QConstant;
import com.io7m.quarrel.ext.logback.QLogback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static java.lang.Boolean.FALSE;

/**
 * Download certificates from looseleaf databases.
 */

public final class CSLooseleafDownload implements QCommandType
{
  private static final Logger LOG =
    LoggerFactory.getLogger(CSLooseleafDownload.class);

  private static final QParameterNamed1<String> ENDPOINT =
    new QParameterNamed1<>(
      "--endpoint",
      List.of(),
      new QConstant("The target looseleaf endpoint base."),
      Optional.empty(),
      String.class
    );

  private static final QParameterNamed1<Path> OUTPUT_DIRECTORY =
    new QParameterNamed1<>(
      "--output-directory",
      List.of(),
      new QConstant("The output directory."),
      Optional.empty(),
      Path.class
    );

  private static final QParameterNamed1<String> DOMAIN =
    new QParameterNamed1<>(
      "--domain",
      List.of(),
      new QConstant("The domain name."),
      Optional.empty(),
      String.class
    );

  private static final QParameterNamed1<String> USERNAME =
    new QParameterNamed1<>(
      "--username",
      List.of(),
      new QConstant("The user name."),
      Optional.empty(),
      String.class
    );

  private static final QParameterNamed1<String> PASSWORD =
    new QParameterNamed1<>(
      "--password",
      List.of(),
      new QConstant("The password."),
      Optional.empty(),
      String.class
    );

  private static final QParameterNamed0N<String> CERTIFICATE_NAME =
    new QParameterNamed0N<>(
      "--certificate-name",
      List.of(),
      new QConstant("The certificate name(s). May be specified multiple times."),
      List.of(),
      String.class
    );

  private static final QParameterNamed1<Boolean> ONLY_ONCE =
    new QParameterNamed1<>(
      "--only-once",
      List.of(),
      new QConstant("Download certificates once and then exit."),
      Optional.of(FALSE),
      Boolean.class
    );

  private static final QParameterNamed1<Duration> SCHEDULE =
    new QParameterNamed1<>(
      "--schedule",
      List.of(),
      new QConstant(
        "Download certificates repeatedly, waiting this duration between attempts."),
      Optional.of(Duration.ofHours(1L)),
      Duration.class
    );

  private List<CSLLDownloader> downloaders;
  private final QCommandMetadata metadata;

  /**
   * Construct a command.
   */

  public CSLooseleafDownload()
  {
    this.metadata = new QCommandMetadata(
      "looseleaf-download",
      new QConstant("Download certificates from looseleaf databases."),
      Optional.empty()
    );
  }

  @Override
  public List<QParameterNamedType<?>> onListNamedParameters()
  {
    return QLogback.plusParameters(
      List.of(
        CERTIFICATE_NAME,
        DOMAIN,
        ENDPOINT,
        ONLY_ONCE,
        OUTPUT_DIRECTORY,
        PASSWORD,
        SCHEDULE,
        USERNAME
      )
    );
  }

  @Override
  public QCommandStatus onExecute(
    final QCommandContextType context)
    throws Exception
  {
    QLogback.configure(context);

    final var outputDirectory =
      context.parameterValue(OUTPUT_DIRECTORY)
        .toAbsolutePath();
    final var endpoint =
      context.parameterValue(ENDPOINT);
    final var domain =
      context.parameterValue(DOMAIN);
    final var userName =
      context.parameterValue(USERNAME);
    final var password =
      context.parameterValue(PASSWORD);
    final var certificateNames =
      context.parameterValues(CERTIFICATE_NAME);
    final var schedule =
      context.parameterValue(SCHEDULE);
    final var onlyOnce =
      context.parameterValue(ONLY_ONCE)
        .booleanValue();

    this.downloaders =
      new ArrayList<>(certificateNames.size());

    for (final var certificateName : certificateNames) {
      this.downloaders.add(
        CSLLDownloader.create(
          outputDirectory,
          endpoint,
          new CSLLCredentials(userName, password),
          domain,
          new CSCertificateName(certificateName)
        )
      );
    }

    while (true) {
      for (final var downloader : this.downloaders) {
        LOG.info(
          "downloading '{}' certificates from '{}'",
          downloader.certificateName().value(),
          endpoint
        );

        try {
          downloader.execute();
        } catch (final IOException e) {
          LOG.error("i/o error: ", e);
          if (onlyOnce) {
            throw e;
          }
        } catch (final InterruptedException e) {
          Thread.currentThread().interrupt();
        }
      }

      if (onlyOnce) {
        break;
      }

      try {
        Thread.sleep(schedule.toMillis());
      } catch (final InterruptedException e) {
        Thread.currentThread().interrupt();
      }
    }

    return QCommandStatus.SUCCESS;
  }

  @Override
  public QCommandMetadata metadata()
  {
    return this.metadata;
  }
}
