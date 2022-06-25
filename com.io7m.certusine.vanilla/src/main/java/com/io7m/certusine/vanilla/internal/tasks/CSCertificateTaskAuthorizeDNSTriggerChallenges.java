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

import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType.CSCertificateTaskCompleted;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType.CSCertificateTaskFailedButCanBeRetried;
import com.io7m.jdeferthrow.core.ExceptionTracker;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;

import static com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType.CSCertificateTaskFailedPermanently;
import static com.io7m.certusine.vanilla.internal.tasks.CSDurations.ACME_UPDATE_PAUSE_TIME;

/**
 * A task that triggers a DNS challenge now that DNS records have (hopefully)
 * been created and propagated.
 */

public final class CSCertificateTaskAuthorizeDNSTriggerChallenges
  extends CSCertificateTask
{
  private static final Logger LOG =
    LoggerFactory.getLogger(CSCertificateTaskAuthorizeDNSTriggerChallenges.class);

  private final Order order;

  /**
   * A task that triggers a DNS challenge now that DNS records have (hopefully)
   * been created and propagated.
   *
   * @param inContext The task context
   * @param inOrder   The ACME order
   */

  public CSCertificateTaskAuthorizeDNSTriggerChallenges(
    final CSCertificateTaskContext inContext,
    final Order inOrder)
  {
    super(inContext);
    this.order = Objects.requireNonNull(inOrder, "order");
  }

  @Override
  CSCertificateTaskStatusType executeActual()
  {
    LOG.debug("triggering DNS challenges");

    final var exceptions =
      new ExceptionTracker<CSCertificateTaskException>();
    final var context =
      this.context();

    for (final var auth : this.order.getAuthorizations()) {
      final Dns01Challenge challenge =
        auth.findChallenge(Dns01Challenge.TYPE);

      if (challenge == null) {
        throw new IllegalStateException("Missing DNS challenge!");
      }

      try {
        final var challengeStatus = challenge.getStatus();
        switch (challengeStatus) {
          case INVALID -> {
            return new CSCertificateTaskFailedPermanently(
              new CSCertificateTaskException(
                context.formatProblem(this.order.getError()),
                false
              )
            );
          }

          case PENDING -> {
            LOG.debug(
              "triggering challenge for authorization {}",
              auth.getIdentifier().getDomain());
            challenge.trigger();
          }
          case READY, UNKNOWN, CANCELED, EXPIRED, DEACTIVATED, REVOKED, VALID, PROCESSING -> {
            LOG.debug(
              "challenge status for authorization {} is {}, so not triggering",
              auth.getIdentifier().getDomain(),
              challengeStatus
            );
          }
        }
      } catch (final AcmeException e) {
        exceptions.addException(new CSCertificateTaskException(e, true));
      }
    }

    try {
      exceptions.throwIfNecessary();
    } catch (final Exception e) {
      return new CSCertificateTaskFailedButCanBeRetried(
        ACME_UPDATE_PAUSE_TIME,
        e
      );
    }

    return new CSCertificateTaskCompleted(
      OptionalLong.empty(),
      Optional.of(new CSCertificateTaskAuthorizeDNSUpdateChallenges(
        context,
        this.order
      ))
    );
  }
}
