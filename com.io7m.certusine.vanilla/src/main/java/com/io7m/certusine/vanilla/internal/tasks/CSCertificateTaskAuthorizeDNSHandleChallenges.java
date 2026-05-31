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
import com.io7m.jdeferthrow.core.ExceptionTracker;
import io.opentelemetry.api.trace.Span;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Optional;
import java.util.OptionalLong;

import static com.io7m.certusine.api.CSTelemetryServiceType.recordExceptionAndSetError;
import static com.io7m.certusine.vanilla.internal.tasks.CSDurations.ACME_UPDATE_PAUSE_TIME;
import static io.opentelemetry.api.trace.StatusCode.ERROR;

/**
 * A task that handles challenges.
 */

public final class CSCertificateTaskAuthorizeDNSHandleChallenges
  extends CSCertificateTaskAuthorizeDNS
{
  private static final Logger LOG =
    LoggerFactory.getLogger(CSCertificateTaskAuthorizeDNSHandleChallenges.class);

  /**
   * A task that handles challenges.
   *
   * @param inContext The task context
   */

  public CSCertificateTaskAuthorizeDNSHandleChallenges(
    final CSCertificateTaskContext inContext)
  {
    super("AuthorizeDNSHandleChallenges", inContext);
  }

  @Override
  CSCertificateTaskStatusType executeActual()
  {
    final var context =
      this.context();

    final Order order;
    try {
      order = context.createOrGetOrder();
    } catch (final AcmeException e) {
      final var ex =
        new CSCertificateTaskException(
          context.strings().format("errorAllTasksFailed"), false
        );
      recordExceptionAndSetError(ex);
      return context.failedPermanently(ex);
    }

    final var triggerStatus = this.challengesTrigger(order);
    if (triggerStatus instanceof CSCertificateTaskCompleted) {
      return this.challengesUpdate(order);
    }
    return triggerStatus;
  }

  private CSCertificateTaskStatusType challengesUpdate(
    final Order order)
  {
    LOG.debug("Updating DNS challenges");

    final var context =
      this.context();

    final var challenges =
      new HashMap<URI, Challenge>();
    final var challengesFailed =
      new HashMap<URI, Challenge>();
    final var challengesSucceeded =
      new HashMap<URI, Challenge>();
    final var exceptions =
      new ExceptionTracker<CSCertificateTaskException>();

    for (var attempt = 0; attempt < 10; ++attempt) {
      this.updateAllChallengesIfRequired(
        order,
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

      if (challengesSucceeded.size() == challenges.size()) {
        context.events()
          .emit(new CSEventCertificateRenewalSucceeded(
            context.domain(),
            context.certificate().name()
          ));

        return new CSCertificateTaskCompleted(
          OptionalLong.empty(),
          Optional.of(
            new CSCertificateTaskSignCertificateInitial(context))
        );
      }

      /*
       * If all the challenges are failed, then retrying isn't going to help
       * and the task ends here.
       */

      if (challengesFailed.size() == challenges.size()) {
        final var ex =
          new CSCertificateTaskException(
            context.strings().format("errorAllTasksFailed"), false
          );
        recordExceptionAndSetError(ex);
        return context.failedPermanently(ex);
      }
    }

    /*
     * If we've reached this far, then at least some of the challenges are
     * still pending. In practice, this seems to be a failure condition: The
     * challenges will keep being in the PENDING state no matter what. The
     * only correct approach is to destroy the order and redo this whole
     * task, at which point the challenges will succeed.
     *
     * See: https://github.com/shred/acme4j/issues/77
     */

    context.destroyOrder();
    return new CSCertificateTaskFailedAndRestart(
      ACME_UPDATE_PAUSE_TIME,
      new CSCertificateTaskAuthorizeDNSInitial(context)
    );
  }

  private CSCertificateTaskStatusType challengesTrigger(
    final Order order)
  {
    LOG.debug("Triggering DNS challenges");

    final var exceptions =
      new ExceptionTracker<CSCertificateTaskException>();
    final var context =
      this.context();

    for (final var auth : order.getAuthorizations()) {
      final var challenge =
        auth.findChallenge(Dns01Challenge.TYPE)
          .orElseThrow(() -> {
            return new IllegalStateException("Missing DNS challenge!");
          });

      try {
        final var challengeStatus = challenge.getStatus();
        switch (challengeStatus) {
          case INVALID -> {
            final var ex =
              new CSCertificateTaskException(
                context.formatProblem(
                  order.getError()
                    .orElseThrow(() -> {
                      return new IllegalStateException("Missing problem report!");
                    })
                ),
                false
              );
            recordExceptionAndSetError(ex);
            return context.failedPermanently(ex);
          }

          case VALID,
               READY,
               UNKNOWN,
               CANCELED,
               EXPIRED,
               DEACTIVATED,
               REVOKED,
               PROCESSING -> {
            LOG.debug(
              "Challenge status for authorization {} is {}, so not triggering",
              auth.getIdentifier().getDomain(),
              challengeStatus
            );
          }

          case PENDING -> {
            LOG.debug(
              "Triggering challenge for authorization {}",
              auth.getIdentifier().getDomain());
            challenge.trigger();
          }

        }
      } catch (final AcmeException e) {
        exceptions.addException(new CSCertificateTaskException(e, true));
      }
    }

    try {
      exceptions.throwIfNecessary();
    } catch (final Exception e) {
      recordExceptionAndSetError(e);
      return new CSCertificateTaskFailedButCanBeRetried(
        ACME_UPDATE_PAUSE_TIME, e);
    }

    return new CSCertificateTaskCompleted(
      OptionalLong.empty(),
      Optional.of(
        new CSCertificateTaskSignCertificateInitial(context)
      )
    );
  }

  private void updateAllChallengesIfRequired(
    final Order order,
    final HashMap<URI, Challenge> challenges,
    final HashMap<URI, Challenge> challengesFailed,
    final HashMap<URI, Challenge> challengesSucceeded,
    final ExceptionTracker<CSCertificateTaskException> exceptions)
  {
    final var context = this.context();

    for (final var auth : order.getAuthorizations()) {
      final var challenge =
        auth.findChallenge(Dns01Challenge.TYPE)
          .orElseThrow(() -> {
            final var ex = new IllegalStateException("Missing DNS challenge!");
            recordExceptionAndSetError(ex);
            return ex;
          });

      final URI uri;
      try {
        uri = challenge.getLocation().toURI();
      } catch (final URISyntaxException e) {
        throw new IllegalStateException(e);
      }

      challenges.put(uri, challenge);

      final var status = challenge.getStatus();
      LOG.debug(
        "Challenge Status [{}]: {}",
        auth.getIdentifier(),
        status
      );

      switch (status) {
        case VALID -> {
          challengesSucceeded.put(uri, challenge);
        }

        case PENDING, UNKNOWN, PROCESSING, READY -> {
          try {
            LOG.debug("Fetching challenge status.");
            final var waitUntilOpt = challenge.fetch();

            final Instant waitUntil;
            if (waitUntilOpt.isPresent()) {
              waitUntil = waitUntilOpt.get();
            } else {
              LOG.debug("No challenge update wait time was provided.");
              waitUntil = Instant.now().plusSeconds(10L);
            }

            while (challenge.getStatus() != Status.VALID) {
              LOG.debug("Waiting until {} to update challenge.", waitUntil);

              final var timeNow = Instant.now();
              if (timeNow.isAfter(waitUntil)) {
                break;
              }

              try {
                Thread.sleep(1_000L);
              } catch (final InterruptedException e) {
                Thread.currentThread().interrupt();
              }
            }

            if (challenge.getStatus() == Status.VALID) {
              LOG.debug("Challenge is now VALID");
              challengesSucceeded.put(uri, challenge);
            }
          } catch (final AcmeException e) {
            exceptions.addException(new CSCertificateTaskException(e, true));
          }
        }

        case INVALID, REVOKED, DEACTIVATED, EXPIRED, CANCELED -> {
          LOG.error(
            "Challenge failed: {}",
            context.formatProblem(
              challenge.getError()
                .orElseThrow(() -> {
                  return new IllegalStateException("Missing problem report!");
                })
            )
          );
          Span.current().setStatus(ERROR);
          challengesFailed.put(uri, challenge);
        }
      }
    }
  }
}
