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

import com.io7m.certusine.api.CSDomain;
import com.io7m.certusine.certstore.api.CSCertificateStored;
import com.io7m.certusine.vanilla.internal.CSCertificateIO;
import com.io7m.certusine.vanilla.internal.events.CSEventCertificateStoreFailed;
import com.io7m.certusine.vanilla.internal.events.CSEventCertificateStored;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType.CSCertificateTaskCompleted;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType.CSCertificateTaskFailedButCanBeRetried;
import io.opentelemetry.api.trace.Span;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.Order;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;

import static com.io7m.certusine.vanilla.internal.tasks.CSDurations.IO_RETRY_PAUSE_TIME;

/**
 * A task that saves signed certificates.
 */

public final class CSCertificateTaskSignCertificateSaveToStore
  extends CSCertificateTaskSignCertificate
{
  private static final Logger LOG =
    LoggerFactory.getLogger(CSCertificateTaskSignCertificateSaveToStore.class);

  private final Order order;

  /**
   * A task that saves signed certificates.
   *
   * @param inContext The task execution context
   * @param inOrder   The certificate order
   */

  public CSCertificateTaskSignCertificateSaveToStore(
    final CSCertificateTaskContext inContext,
    final Order inOrder)
  {
    super("SignCertificateSaveToStore", inContext);
    this.order = Objects.requireNonNull(inOrder, "order");
  }

  @Override
  CSCertificateTaskStatusType executeActual()
    throws InterruptedException
  {
    LOG.info("saving certificate to local database");

    final var issuedCertificate =
      this.order.getCertificate();
    final var context =
      this.context();
    final var domain =
      context.domain();

    try {
      this.saveCertificateLocally(issuedCertificate, domain);
    } catch (final IOException e) {
      Span.current().recordException(e);
      LOG.error("failed to save certificate to the local database: ", e);
      return new CSCertificateTaskFailedButCanBeRetried(IO_RETRY_PAUSE_TIME, e);
    }

    return new CSCertificateTaskCompleted(
      OptionalLong.empty(),
      Optional.of(
        new CSCertificateTaskSignCertificateSaveToOutputs(context)
      )
    );
  }

  @Override
  void executeOnTaskCompletelyFailed()
  {
    final CSCertificateTaskContext context = this.context();
    context.events()
      .emit(new CSEventCertificateStoreFailed(
        context.domain(),
        context.certificate().name(),
        "local"
      ));
  }

  private void saveCertificateLocally(
    final Certificate issuedCertificate,
    final CSDomain domain)
    throws IOException
  {
    final var context =
      this.context();
    final var createdOn =
      OffsetDateTime.now(context.clock());
    final var x509Certificate =
      issuedCertificate.getCertificate();
    final var expiresOn =
      OffsetDateTime.ofInstant(
        x509Certificate.getNotAfter().toInstant(),
        ZoneId.systemDefault()
      );

    final var encodedCertificate =
      CSCertificateIO.encodeCertificate(x509Certificate);
    final var encodedCertificateChain =
      CSCertificateIO.encodeCertificates(issuedCertificate.getCertificateChain());

    context.certificateStore()
      .put(
        new CSCertificateStored(
          domain.domain(),
          context.certificate().name(),
          createdOn,
          expiresOn,
          encodedCertificate,
          encodedCertificateChain
        )
      );

    context.events()
      .emit(new CSEventCertificateStored(
        context.domain(),
        context.certificate().name(),
        "local"
      ));
  }
}
