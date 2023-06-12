/*
 * Copyright © 2023 Mark Raynsford <code@io7m.com> https://www.io7m.com
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

package com.io7m.certusine.vanilla.internal.configuration;

import com.io7m.anethum.api.ParsingException;
import com.io7m.certusine.api.CSConfiguration;
import com.io7m.certusine.api.CSConfigurationParsersType;
import com.io7m.certusine.api.CSConfigurationServiceType;
import com.io7m.certusine.api.CSParseErrorLogging;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.Flow;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.SubmissionPublisher;
import java.util.concurrent.TimeUnit;

/**
 * A configuration service that continually reloads the configuration.
 */

public final class CSConfigurationService
  implements CSConfigurationServiceType
{
  private static final Logger LOG =
    LoggerFactory.getLogger(CSConfigurationService.class);

  private final ScheduledExecutorService executor;
  private final CSConfigurationParsersType parsers;
  private final Path baseDirectory;
  private final Path configurationFile;
  private final SubmissionPublisher<CSConfiguration> eventSubject;
  private volatile CSConfiguration configuration;

  private CSConfigurationService(
    final ScheduledExecutorService inExecutor,
    final CSConfigurationParsersType inParsers,
    final Path inBaseDirectory,
    final Path inConfigurationFile,
    final CSConfiguration inConfiguration)
  {
    this.executor =
      Objects.requireNonNull(inExecutor, "executor");
    this.parsers =
      Objects.requireNonNull(inParsers, "parsers");
    this.baseDirectory =
      Objects.requireNonNull(inBaseDirectory, "baseDirectory");
    this.configurationFile =
      Objects.requireNonNull(inConfigurationFile, "configurationFile");
    this.configuration =
      Objects.requireNonNull(inConfiguration, "configuration");
    this.eventSubject =
      new SubmissionPublisher<>();
  }

  /**
   * Create a configuration service.
   *
   * @param parsers           The configuration parsers
   * @param baseDirectory     The base directory
   * @param configurationFile The configuration file
   * @param configuration     The initial configuration
   *
   * @return A configuration service
   */

  public static CSConfigurationServiceType create(
    final CSConfigurationParsersType parsers,
    final Path baseDirectory,
    final Path configurationFile,
    final CSConfiguration configuration)
  {
    Objects.requireNonNull(parsers, "parsers");
    Objects.requireNonNull(baseDirectory, "baseDirectory");
    Objects.requireNonNull(configurationFile, "configurationFile");
    Objects.requireNonNull(configuration, "configuration");

    final var executor =
      Executors.newSingleThreadScheduledExecutor(r -> {
        final var thread = new Thread(r);
        thread.setDaemon(true);
        thread.setName("com.io7m.certusine.configuration[%d]"
                         .formatted(thread.getId()));
        return thread;
      });

    final CSConfigurationService service =
      new CSConfigurationService(
        executor,
        parsers,
        baseDirectory,
        configurationFile,
        configuration
      );

    executor.scheduleAtFixedRate(service::reload, 5L, 5L, TimeUnit.SECONDS);
    return service;
  }

  @Override
  public String description()
  {
    return "Configuration service.";
  }

  @Override
  public CSConfiguration configuration()
  {
    return this.configuration;
  }

  @Override
  public void reload()
  {
    try {
      final CSConfiguration newConfiguration =
        this.parsers.parseFileWithContext(
        this.baseDirectory,
        this.configurationFile
      );

      if (!Objects.equals(newConfiguration, this.configuration)) {
        this.eventSubject.submit(newConfiguration);
      }

      this.configuration = newConfiguration;
    } catch (final IOException e) {
      LOG.error("error reloading configuration: ", e);
    } catch (final ParsingException e) {
      LOG.error("error reloading configuration: ", e);
      CSParseErrorLogging.logParseErrors(LOG, this.configurationFile, e);
    }
  }

  @Override
  public Flow.Publisher<CSConfiguration> events()
  {
    return this.eventSubject;
  }

  @Override
  public void close()
    throws Exception
  {
    this.executor.shutdown();
    this.eventSubject.close();
  }
}
