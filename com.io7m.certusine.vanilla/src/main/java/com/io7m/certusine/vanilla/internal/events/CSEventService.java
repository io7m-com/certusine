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

import com.io7m.certusine.api.CSCertificateName;
import com.io7m.certusine.api.CSConfigurationServiceType;
import com.io7m.certusine.api.CSTelemetryServiceType;
import com.io7m.jmulticlose.core.CloseableCollection;
import com.io7m.jmulticlose.core.CloseableCollectionType;
import com.io7m.jmulticlose.core.ClosingResourceFailedException;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.logs.Severity;
import io.opentelemetry.api.metrics.LongCounter;
import io.opentelemetry.api.metrics.ObservableLongGauge;
import io.opentelemetry.api.metrics.ObservableLongMeasurement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

import java.util.concurrent.ConcurrentHashMap;

import static io.opentelemetry.api.common.AttributeKey.stringKey;

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
  private final ObservableLongGauge up;
  private final io.opentelemetry.api.logs.Logger logger;
  private final ConcurrentHashMap<FullyQualifiedCertificate, Long> certificatesRemaining;
  private final ObservableLongGauge certificateRemaining;
  private final ObservableLongGauge renewalThreshold;
  private final CloseableCollectionType<ClosingResourceFailedException> resources;

  private CSEventService(
    final CSConfigurationServiceType configuration,
    final CSTelemetryServiceType telemetry)
  {
    this.certificatesRemaining =
      new ConcurrentHashMap<>();

    this.resources =
      CloseableCollection.create();

    this.up =
      this.resources.add(
        telemetry.meter()
          .gaugeBuilder("certusine_up")
          .ofLongs()
          .buildWithCallback(measurement -> measurement.record(1L))
      );

    this.renewalThreshold =
      this.resources.add(
        telemetry.meter()
          .gaugeBuilder("certusine_certificate_expiration_threshold")
          .setDescription("The certificate expiration threshold in seconds.")
          .ofLongs()
          .buildWithCallback(measurement -> {
            reportRenewalThreshold(configuration, measurement);
          })
      );

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
        .setDescription("The number of times certificates have been stored.")
        .build();

    this.storeFailures =
      telemetry.meter()
        .counterBuilder("certusine_certificates_store_failures")
        .setDescription(
          "The number of times certificates have failed to store.")
        .build();

    this.certificateRemaining =
      this.resources.add(
        telemetry.meter()
          .gaugeBuilder("certusine_certificate_time_remaining")
          .setDescription(
            "The time remaining before a certificate expires (seconds).")
          .ofLongs()
          .buildWithCallback(this::reportCertificateAges)
      );

    this.logger =
      telemetry.logger();
  }

  private static void reportRenewalThreshold(
    final CSConfigurationServiceType configuration,
    final ObservableLongMeasurement measurement)
  {
    measurement.record(
      configuration.configuration()
        .options()
        .certificateExpirationThreshold()
        .toSeconds()
    );
  }

  /**
   * Create a new event service.
   *
   * @param configuration The configuration service
   * @param telemetry     The telemetry
   *
   * @return A new event service
   */

  public static CSEventServiceType create(
    final CSConfigurationServiceType configuration,
    final CSTelemetryServiceType telemetry)
  {
    return new CSEventService(configuration, telemetry);
  }

  private static void publishLog(
    final CSEventType event)
  {
    if (event.isLogged()) {
      var builder =
        LOG.makeLoggingEventBuilder(
          event.isFailure() ? Level.ERROR : Level.INFO
        );

      builder = builder.setMessage("[event] " + event.message());
      builder = builder.addKeyValue(
        "certusine.type",
        event.getClass().getSimpleName()
      );

      for (final var entry : event.attributes().entrySet()) {
        builder = builder.addKeyValue(entry.getKey(), entry.getValue());
      }

      builder.log();
    }
  }

  private void reportCertificateAges(
    final ObservableLongMeasurement measurement)
  {
    for (final var entry : this.certificatesRemaining.entrySet()) {
      final var key = entry.getKey();
      final var age = entry.getValue();
      final var attributes =
        Attributes.builder()
          .put("domain", key.domainName())
          .put("certificate", key.name().value())
          .build();
      measurement.record(age.longValue(), attributes);
    }
  }

  @Override
  public void emit(
    final CSEventType event)
  {
    this.publishTelemetry(event);
    publishLog(event);
    this.incrementMeters(event);
  }

  private void publishTelemetry(
    final CSEventType event)
  {
    if (event.isLogged()) {
      final var builder =
        this.logger.logRecordBuilder();

      builder.setBody(event.message());
      builder.setSeverity(event.isFailure() ? Severity.ERROR : Severity.INFO);
      builder.setAttribute(
        stringKey("certusine.type"),
        event.getClass().getSimpleName()
      );

      for (final var entry : event.attributes().entrySet()) {
        builder.setAttribute(stringKey(entry.getKey()), entry.getValue());
      }

      builder.emit();
    }
  }

  private void incrementMeters(
    final CSEventType event)
  {
    if (event instanceof final CSEventCertificateRenewalSucceeded e) {
      final var attributes =
        Attributes.builder()
          .put("domain", e.domain().domain())
          .put("certificate", e.certificateName().value())
          .build();

      this.renewalSuccesses.add(1L, attributes);
    }

    if (event instanceof final CSEventCertificateRenewalFailed e) {
      final var attributes =
        Attributes.builder()
          .put("domain", e.domain().domain())
          .put("certificate", e.certificateName().value())
          .build();
      this.renewalFailures.add(1L, attributes);
    }

    if (event instanceof final CSEventCertificateStored e) {
      final var attributes =
        Attributes.builder()
          .put("domain", e.domain().domain())
          .put("certificate", e.certificateName().value())
          .build();
      this.stores.add(1L, attributes);
    }

    if (event instanceof final CSEventCertificateStoreFailed e) {
      final var attributes =
        Attributes.builder()
          .put("domain", e.domain().domain())
          .put("certificate", e.certificateName().value())
          .put("target", e.target())
          .build();
      this.storeFailures.add(1L, attributes);
    }

    if (event instanceof final CSEventCertificateDNSChallengeFailed e) {
      final var attributes =
        Attributes.builder()
          .put("domain", e.domain().domain())
          .put("certificate", e.certificateName().value())
          .build();
      this.dnsChallengeFailures.add(1L, attributes);
    }

    if (event instanceof final CSEventCertificateSigningFailed e) {
      final var attributes =
        Attributes.builder()
          .put("domain", e.domain().domain())
          .put("certificate", e.certificateName().value())
          .build();
      this.signingFailures.add(1L, attributes);
    }

    if (event instanceof final CSEventCertificateValidityRemaining remaining) {
      this.certificatesRemaining.put(
        new FullyQualifiedCertificate(
          remaining.domain(),
          remaining.certificateName()
        ),
        Long.valueOf(remaining.seconds())
      );
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
    this.resources.close();
  }

  private record FullyQualifiedCertificate(
    String domainName,
    CSCertificateName name)
  {

  }
}
