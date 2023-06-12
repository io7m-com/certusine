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

package com.io7m.certusine.vanilla.internal.tasks;

import com.io7m.certusine.api.CSFaultInjectionConfiguration;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType.CSCertificateTaskCompleted;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType.CSCertificateTaskFailedButCanBeRetried;
import io.opentelemetry.api.trace.Span;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.time.Duration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;

import static com.io7m.certusine.api.CSTelemetryServiceType.recordExceptionAndSetError;
import static com.io7m.certusine.vanilla.internal.tasks.CSDurations.ACME_UPDATE_PAUSE_TIME;

/**
 * The initial task that searches for a DNS challenge, and creates DNS records
 * in response.
 */

public final class CSCertificateTaskAuthorizeDNSInitial
  extends CSCertificateTaskAuthorizeDNS
{
  private static final Logger LOG =
    LoggerFactory.getLogger(CSCertificateTaskAuthorizeDNSInitial.class);

  private final Order order;

  /**
   * The initial task that searches for a DNS challenge, and creates DNS records
   * in response.
   *
   * @param inContext The task context
   * @param inOrder   The ACME order
   */

  public CSCertificateTaskAuthorizeDNSInitial(
    final CSCertificateTaskContext inContext,
    final Order inOrder)
  {
    super("AuthorizeDNSInitial", inContext);
    this.order = Objects.requireNonNull(inOrder, "order");
  }

  @Override
  CSCertificateTaskStatusType executeActual()
    throws InterruptedException
  {
    final var context =
      this.context();

    LOG.info("checking if domain is authorized");

    try {

      /*
       * Do any required fault injection.
       */

      final var faultInjection =
        context.options().faultInjection();

      injectFaultCrash(faultInjection);

      if (faultInjection.failDNSChallenge()) {
        return context.failedPermanently(
          new RuntimeException("InjectedFaultDNSFailure")
        );
      }

      final var domainNames =
        new HashMap<String, String>();
      final var authorizations =
        new HashSet<Authorization>();
      final var authorizationsValid =
        new HashSet<Authorization>();

      this.checkAuthorizationsValidity(
        context,
        domainNames,
        authorizations,
        authorizationsValid
      );

      /*
       * If all the authorizations are already valid, we can jump straight
       * to getting signed certificates.
       */

      if (authorizationsValid.size() == authorizations.size()) {
        LOG.info("domain is already authorized");
        return new CSCertificateTaskCompleted(
          OptionalLong.empty(),
          Optional.of(
            new CSCertificateTaskSignCertificateInitial(context, this.order))
        );
      }

      /*
       * Otherwise, at least one authorization needs to have challenges
       * completed.
       */

      LOG.info("domain requires authorization");
      return new CSCertificateTaskCompleted(
        OptionalLong.of(context.options().dnsWaitTime().toMillis()),
        Optional.of(
          new CSCertificateTaskAuthorizeDNSCheckRecords(
            context, this.order, domainNames)
        )
      );
    } catch (final CSCertificateTaskException e) {
      LOG.error("error checking authorization: ", e);
      recordExceptionAndSetError(e);

      if (e.canRetry()) {
        LOG.info("retrying...");
        return new CSCertificateTaskFailedButCanBeRetried(
          ACME_UPDATE_PAUSE_TIME,
          e
        );
      }
      return context.failedPermanently(e);
    }
  }

  private static void injectFaultCrash(
    final CSFaultInjectionConfiguration faultInjection)
  {
    if (faultInjection.crashDNSChallenge()) {
      Span.current().addEvent("InjectedFaultDNSCrash");
      throw new RuntimeException("InjectedFaultDNSCrash");
    }
  }

  private void checkAuthorizationsValidity(
    final CSCertificateTaskContext context,
    final HashMap<String, String> domainNames,
    final HashSet<Authorization> authorizations,
    final HashSet<Authorization> authorizationsValid)
    throws CSCertificateTaskException, InterruptedException
  {
    final var span =
      context.telemetry()
        .tracer()
        .spanBuilder("CheckAuthorizationsValidity")
        .startSpan();

    try (var ignored = span.makeCurrent()) {
      for (final var auth : this.order.getAuthorizations()) {
        this.checkAuthorizationValidity(
          context,
          domainNames,
          authorizations,
          authorizationsValid,
          auth);
      }
    } finally {
      span.end();
    }
  }

  private void checkAuthorizationValidity(
    final CSCertificateTaskContext context,
    final HashMap<String, String> domainNames,
    final HashSet<Authorization> authorizations,
    final HashSet<Authorization> authorizationsValid,
    final Authorization auth)
    throws CSCertificateTaskException, InterruptedException
  {
    final var span =
      context.telemetry()
        .tracer()
        .spanBuilder("CheckAuthorizationValidity")
        .startSpan();

    try (var ignored = span.makeCurrent()) {
      authorizations.add(auth);

      if (auth.getStatus() == Status.VALID) {
        LOG.debug("authorization is already valid");
        authorizationsValid.add(auth);
        return;
      }

      final var entry = this.startDomainAuthorization(context, auth);
      domainNames.put(entry.getKey(), entry.getValue());

      final var timeNow =
        context.now().toInstant();
      final var timeExpires =
        auth.getExpires();

      LOG.debug(
        "authorization will expire in {}",
        Duration.between(timeNow, timeExpires)
      );
    } finally {
      span.end();
    }
  }

  private Map.Entry<String, String> startDomainAuthorization(
    final CSCertificateTaskContext context,
    final Authorization auth)
    throws CSCertificateTaskException, InterruptedException
  {
    final var domainName =
      auth.getIdentifier()
        .getDomain();

    final var span =
      context.telemetry()
        .tracer()
        .spanBuilder("StartDomainChallenge")
        .setAttribute("certusine.domain", domainName)
        .startSpan();

    try (var ignored = span.makeCurrent()) {
      LOG.debug("executing authorization");

      final Dns01Challenge challenge = auth.findChallenge(Dns01Challenge.TYPE);
      if (challenge == null) {
        throw new CSCertificateTaskException(
          this.context().strings().format(
            "challengeTypeUnavailable",
            Dns01Challenge.TYPE),
          false
        );
      }

      final var recordName =
        this.txtRecordNameToSet(domainName);
      final var recordText =
        injectFault(context, challenge.getDigest());

      try {
        LOG.info("creating required DNS TXT records");
        this.context()
          .domain()
          .dnsConfigurator()
          .createTXTRecord(
            this.context().telemetry(),
            recordName,
            recordText
          );
      } catch (final IOException e) {
        throw new CSCertificateTaskException(e, true);
      }

      return Map.entry(domainName, recordText);
    } catch (final Exception e) {
      span.recordException(e);
      throw e;
    } finally {
      span.end();
    }
  }

  private static String injectFault(
    final CSCertificateTaskContext context,
    final String digest)
  {
    if (isFaultInjectingFailingDNSChallenges(context)) {
      Span.current().addEvent("InjectedFaultDNSCorruption");
      return new StringBuilder(digest).reverse().toString();
    }
    return digest;
  }

  private static boolean isFaultInjectingFailingDNSChallenges(
    final CSCertificateTaskContext context)
  {
    return context.options().faultInjection().failDNSChallenge();
  }
}
