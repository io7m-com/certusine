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

import com.io7m.certusine.api.CSCertificate;
import com.io7m.certusine.api.CSDomain;
import com.io7m.certusine.certstore.api.CSCertificateStoreType;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.CSRBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;

import static com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType.CSCertificateTaskCompleted;
import static com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType.CSCertificateTaskFailedPermanently;
import static com.io7m.certusine.vanilla.internal.tasks.CSDurations.ACME_UPDATE_PAUSE_TIME;

/**
 * A task that begins certificate signing.
 */

public final class CSCertificateTaskSignCertificateInitial
  extends CSCertificateTask
{
  private static final Logger LOG =
    LoggerFactory.getLogger(CSCertificateTaskSignCertificateInitial.class);

  private final Order order;

  /**
   * A task that begins certificate signing.
   *
   * @param inContext The task execution context
   * @param inOrder   The certificate order
   */

  public CSCertificateTaskSignCertificateInitial(
    final CSCertificateTaskContext inContext,
    final Order inOrder)
  {
    super(inContext);
    this.order = Objects.requireNonNull(inOrder, "order");
  }

  /**
   * Determine if the certificate expires soon enough that a renewal is
   * warranted. If the certificate doesn't exist, this is automatically assumed
   * to be true.
   */

  private static boolean certificateExpiresSoon(
    final CSDomain domain,
    final CSCertificate certificate,
    final CSCertificateTaskContext context,
    final CSCertificateStoreType store)
    throws IOException
  {
    final var existingOpt =
      store.find(domain.domain(), certificate.name());

    if (existingOpt.isPresent()) {
      final var storedCertificate =
        existingOpt.get();
      final var timeNow =
        OffsetDateTime.now(context.clock());
      final var timeExpires =
        storedCertificate.expiresOn();
      final var durationUntil =
        Duration.between(timeNow, timeExpires);
      final var durationThreshold =
        context.options().certificateExpirationThreshold();

      return durationUntil.compareTo(durationThreshold) <= 0;
    }

    return true;
  }

  @Override
  CSCertificateTaskStatusType executeActual()
  {
    LOG.info("checking if certificates require reissuing");

    final var context =
      this.context();
    final var domain =
      context.domain();
    final var certificate =
      context.certificate();
    final var store =
      context.certificateStore();

    try {

      /*
       * If the certificate expires soon, then order a renewal. A nonexistent
       * certificate is assumed to require a renewal.
       */

      if (certificateExpiresSoon(domain, certificate, context, store)) {
        LOG.info("certificates require reissuing, sending a signing request...");

        final var csrb = new CSRBuilder();
        csrb.addDomains(certificate.fullyQualifiedHostNames(domain));
        csrb.sign(certificate.keyPair());
        this.order.execute(csrb.getEncoded());

        return new CSCertificateTaskCompleted(
          ACME_UPDATE_PAUSE_TIME,
          Optional.of(
            new CSCertificateTaskSignCertificateUpdate(context, this.order))
        );
      }

      /*
       * There appears to be no reason to renew the certificate yet.
       */

      LOG.info("certificates do not require reissuing");
      return new CSCertificateTaskCompleted(
        OptionalLong.empty(),
        Optional.of(
          new CSCertificateTaskSignCertificateSaveToOutputs(
            context,
            this.order))
      );
    } catch (final IOException | AcmeException e) {
      LOG.error("failed to submit a signing request: {}", e.getMessage());
      return new CSCertificateTaskFailedPermanently(e);
    }
  }
}
