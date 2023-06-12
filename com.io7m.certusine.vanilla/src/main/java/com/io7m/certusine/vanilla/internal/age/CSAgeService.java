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


package com.io7m.certusine.vanilla.internal.age;

import com.io7m.certusine.vanilla.internal.events.CSEventCertificateValidityRemaining;
import com.io7m.certusine.vanilla.internal.events.CSEventServiceType;
import com.io7m.certusine.vanilla.internal.store.CSCertificateStoreServiceType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import static java.util.concurrent.TimeUnit.SECONDS;

/**
 * An age service for certificates.
 */

public final class CSAgeService implements CSAgeServiceType
{
  private static final Logger LOG =
    LoggerFactory.getLogger(CSAgeService.class);

  private final Clock clock;
  private final ScheduledExecutorService executor;
  private final CSCertificateStoreServiceType stores;
  private final CSEventServiceType events;

  private CSAgeService(
    final Clock inClock,
    final ScheduledExecutorService inExecutor,
    final CSCertificateStoreServiceType inStores,
    final CSEventServiceType inEvents)
  {
    this.clock =
      Objects.requireNonNull(inClock, "clock");
    this.executor =
      Objects.requireNonNull(inExecutor, "executor");
    this.stores =
      Objects.requireNonNull(inStores, "stores");
    this.events =
      Objects.requireNonNull(inEvents, "events");
  }

  /**
   * Create a service.
   * @param clock The clock
   * @param stores The certificate store service
   * @param events The event service
   * @return A service
   */

  public static CSAgeServiceType create(
    final Clock clock,
    final CSCertificateStoreServiceType stores,
    final CSEventServiceType events)
  {
    final var executor =
      Executors.newSingleThreadScheduledExecutor(r -> {
        final var thread = new Thread(r);
        thread.setDaemon(true);
        thread.setName("com.io7m.certusine.age[%d]"
                         .formatted(thread.getId()));
        return thread;
      });

    final var service =
      new CSAgeService(clock, executor, stores, events);
    executor.scheduleAtFixedRate(service::broadcast, 1L, 60L, SECONDS);
    return service;
  }

  private void broadcast()
  {
    try {
      final var certificates =
        this.stores.store().all();

      final var timeNow =
        OffsetDateTime.now(this.clock);

      for (final var certificate : certificates) {
        final var remaining =
          Duration.between(timeNow, certificate.expiresOn());

        this.events.emit(
          new CSEventCertificateValidityRemaining(
            certificate.domain(),
            certificate.name(),
            remaining.toSeconds()
          )
        );
      }
    } catch (final IOException e) {
      LOG.error("error reporting certificate ages: ", e);
    }
  }

  @Override
  public String description()
  {
    return "Certificate age service.";
  }

  @Override
  public void close()
    throws Exception
  {
    this.executor.shutdown();
  }
}
