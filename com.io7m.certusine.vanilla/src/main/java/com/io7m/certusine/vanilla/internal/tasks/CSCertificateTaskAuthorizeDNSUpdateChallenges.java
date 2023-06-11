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

import com.io7m.certusine.vanilla.internal.events.CSEventCertificateRenewalSucceeded;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType.CSCertificateTaskCompleted;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType.CSCertificateTaskFailedButCanBeRetried;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType.CSCertificateTaskInProgress;
import com.io7m.jdeferthrow.core.ExceptionTracker;
import io.opentelemetry.api.trace.Span;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;

import static com.io7m.certusine.vanilla.internal.tasks.CSDurations.ACME_UPDATE_PAUSE_TIME;

/**
 * A task that updates all the DNS challenges that may be in progress.
 */

public final class CSCertificateTaskAuthorizeDNSUpdateChallenges
  extends CSCertificateTaskAuthorizeDNS
{
  private static final Logger LOG =
    LoggerFactory.getLogger(CSCertificateTaskAuthorizeDNSUpdateChallenges.class);

  private final Order order;

  /**
   * A task that updates all the DNS challenges that may be in progress.
   *
   * @param inContext The execution context
   * @param inOrder   The certificate order
   */

  public CSCertificateTaskAuthorizeDNSUpdateChallenges(
    final CSCertificateTaskContext inContext,
    final Order inOrder)
  {
    super("AuthorizeDNSUpdateChallenges", inContext);
    this.order = Objects.requireNonNull(inOrder, "order");
  }

  @Override
  CSCertificateTaskStatusType executeActual()
  {
    LOG.debug("updating DNS challenges");

    final var challenges =
      new HashSet<Dns01Challenge>();
    final var challengesFailed =
      new HashSet<Dns01Challenge>();
    final var challengesSucceeded =
      new HashSet<Dns01Challenge>();
    final var exceptions =
      new ExceptionTracker<CSCertificateTaskException>();

    this.updateAllChallengesIfRequired(
      challenges,
      challengesFailed,
      challengesSucceeded,
      exceptions
    );

    /*
     * The bulk of this task is in considering whether forward progress
     * could be made, based on the statuses of all the challenges.
     *
     * If all the challenges are valid, then the task is completed.
     */

    final var context = this.context();
    if (challengesSucceeded.size() == challenges.size()) {
      context.events()
        .emit(new CSEventCertificateRenewalSucceeded(
          context.domain(),
          context.certificate().name()
        ));

      return new CSCertificateTaskCompleted(
        OptionalLong.empty(),
        Optional.of(
          new CSCertificateTaskSignCertificateInitial(context, this.order))
      );
    }

    /*
     * If all the challenges are failed, then retrying isn't going to help
     * and the task ends here.
     */

    if (challengesFailed.size() == challenges.size()) {
      return context.failedPermanently(
        new CSCertificateTaskException(
          context.strings().format("errorAllTasksFailed"),
          false
        )
      );
    }

    /*
     * Otherwise, some tasks were in a pending state, but there were errors
     * updating them. Retrying again might move them to a different state.
     */

    try {
      exceptions.throwIfNecessary();
    } catch (final Exception e) {
      Span.current().recordException(e);
      return new CSCertificateTaskFailedButCanBeRetried(
        ACME_UPDATE_PAUSE_TIME,
        e
      );
    }

    /*
     * Otherwise, some tasks are still pending, and continuing might complete
     * them.
     */

    return new CSCertificateTaskInProgress(ACME_UPDATE_PAUSE_TIME);
  }

  private void updateAllChallengesIfRequired(
    final HashSet<Dns01Challenge> challenges,
    final HashSet<Dns01Challenge> challengesFailed,
    final HashSet<Dns01Challenge> challengesSucceeded,
    final ExceptionTracker<CSCertificateTaskException> exceptions)
  {
    final var context = this.context();
    for (final var auth : this.order.getAuthorizations()) {
      final Dns01Challenge challenge =
        auth.findChallenge(Dns01Challenge.TYPE);

      if (challenge == null) {
        throw new IllegalStateException("Missing DNS challenge!");
      }
      challenges.add(challenge);

      switch (challenge.getStatus()) {
        case VALID -> {
          challengesSucceeded.add(challenge);
        }

        case PENDING, UNKNOWN, PROCESSING, READY -> {
          try {
            challenge.update();
          } catch (final AcmeException e) {
            exceptions.addException(new CSCertificateTaskException(e, true));
          }
        }

        case INVALID, REVOKED, DEACTIVATED, EXPIRED, CANCELED -> {
          LOG.error(
            "challenge failed: {}",
            context.formatProblem(challenge.getError()));
          challengesFailed.add(challenge);
        }
      }
    }
  }
}
