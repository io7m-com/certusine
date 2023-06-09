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


package com.io7m.certusine.vanilla.internal.events;

import com.io7m.certusine.api.CSTelemetryServiceType;
import io.opentelemetry.api.metrics.LongCounter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.spi.LoggingEventBuilder;

/**
 * The default event service.
 */

public final class CSEventService implements CSEventServiceType
{
  private static final Logger LOG =
    LoggerFactory.getLogger(CSEventService.class);

  private final LongCounter renewalFailures;
  private final LongCounter stores;
  private final LongCounter dnsChallengeFailures;
  private final LongCounter signingFailures;
  private final LongCounter storeFailures;
  private final LongCounter renewalSuccesses;

  private CSEventService(
    final CSTelemetryServiceType telemetry)
  {
    this.dnsChallengeFailures =
      telemetry.meter()
        .counterBuilder("certusine_dns_challenge_failures")
        .setDescription("Certificate DNS challenge failures.")
        .build();

    this.signingFailures =
      telemetry.meter()
        .counterBuilder("certusine_signing_failures")
        .setDescription("Certificate signing failures.")
        .build();

    this.renewalFailures =
      telemetry.meter()
        .counterBuilder("certusine_renewal_failures")
        .setDescription("Certificate renewal failures.")
        .build();

    this.renewalSuccesses =
      telemetry.meter()
        .counterBuilder("certusine_renewal_successes")
        .setDescription("Certificate renewal successes.")
        .build();

    this.stores =
      telemetry.meter()
        .counterBuilder("certusine_certificates_stored")
        .build();

    this.storeFailures =
      telemetry.meter()
        .counterBuilder("certusine_certificates_store_failures")
        .build();
  }

  /**
   * Create a new event service.
   *
   * @param telemetry The telemetry
   *
   * @return A new event service
   */

  public static CSEventServiceType create(
    final CSTelemetryServiceType telemetry)
  {
    return new CSEventService(telemetry);
  }

  @Override
  public void emit(
    final CSEventType event)
  {
    LoggingEventBuilder builder;
    if (event.isFailure()) {
      builder = LOG.atError();
    } else {
      builder = LOG.atInfo();
    }

    builder = builder.setMessage(event.message());
    builder = builder.addKeyValue(
      "certusine.type",
      event.getClass().getSimpleName());
    for (final var entry : event.attributes().entrySet()) {
      builder = builder.addKeyValue(entry.getKey(), entry.getValue());
    }
    builder.log();

    this.incrementMeters(event);
  }

  private void incrementMeters(
    final CSEventType event)
  {
    if (event instanceof CSEventCertificateRenewalSucceeded) {
      this.renewalSuccesses.add(1L);
    }
    if (event instanceof CSEventCertificateRenewalFailed) {
      this.renewalFailures.add(1L);
    }
    if (event instanceof CSEventCertificateStored) {
      this.stores.add(1L);
    }
    if (event instanceof CSEventCertificateStoreFailed) {
      this.storeFailures.add(1L);
    }
    if (event instanceof CSEventCertificateDNSChallengeFailed) {
      this.dnsChallengeFailures.add(1L);
    }
    if (event instanceof CSEventCertificateSigningFailed) {
      this.signingFailures.add(1L);
    }
  }

  @Override
  public String description()
  {
    return "Event service.";
  }

  @Override
  public String toString()
  {
    return "[CSEventService 0x%s]"
      .formatted(Long.toUnsignedString(this.hashCode(), 16));
  }

  @Override
  public void close()
    throws Exception
  {

  }
}
