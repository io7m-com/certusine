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

import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType.CSCertificateTaskFailedPermanently;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType.CSCertificateTaskInProgress;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.exception.AcmeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;

import static com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType.CSCertificateTaskCompleted;
import static com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType.CSCertificateTaskFailedButCanBeRetried;
import static com.io7m.certusine.vanilla.internal.tasks.CSDurations.ACME_UPDATE_PAUSE_TIME;
import static org.shredzone.acme4j.Status.VALID;

/**
 * A certificate task that updates all certificate signing operations that may
 * be in progress.
 */

public final class CSCertificateTaskSignCertificateUpdate
  extends CSCertificateTask
{
  private static final Logger LOG =
    LoggerFactory.getLogger(CSCertificateTaskSignCertificateUpdate.class);

  private final Order order;

  /**
   * A certificate task that updates all certificate signing operations that may
   * be in progress.
   *
   * @param inContext The task execution context
   * @param inOrder   The certificate order
   */

  public CSCertificateTaskSignCertificateUpdate(
    final CSCertificateTaskContext inContext,
    final Order inOrder)
  {
    super(inContext);
    this.order = Objects.requireNonNull(inOrder, "order");
  }

  @Override
  CSCertificateTaskStatusType executeActual()
    throws InterruptedException
  {
    LOG.debug("updating certificate signing order");

    /*
     * If the order status is valid, then move to writing out certificates.
     */

    final var context = this.context();
    if (this.order.getStatus() == VALID) {
      return new CSCertificateTaskCompleted(OptionalLong.empty(), Optional.of(
        new CSCertificateTaskSignCertificateSaveToStore(context, this.order)
      ));
    }

    /*
     * Otherwise, update the order.
     */

    try {
      this.order.update();
    } catch (final AcmeException e) {
      return new CSCertificateTaskFailedButCanBeRetried(
        ACME_UPDATE_PAUSE_TIME, e);
    }

    return switch (this.order.getStatus()) {
      case PENDING, READY, PROCESSING -> {
        yield new CSCertificateTaskInProgress(ACME_UPDATE_PAUSE_TIME);
      }

      case VALID -> {
        yield new CSCertificateTaskCompleted(OptionalLong.empty(), Optional.of(
          new CSCertificateTaskSignCertificateSaveToStore(context, this.order)
        ));
      }

      case INVALID, DEACTIVATED, REVOKED, EXPIRED, CANCELED, UNKNOWN -> {
        yield new CSCertificateTaskFailedPermanently(
          new CSCertificateTaskException(
            context.formatProblem(this.order.getError()),
            false
          )
        );
      }
    };
  }
}
