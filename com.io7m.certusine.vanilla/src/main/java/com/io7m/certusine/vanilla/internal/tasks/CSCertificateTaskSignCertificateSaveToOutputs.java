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

import com.io7m.certusine.api.CSCertificateOutputData;
import com.io7m.certusine.vanilla.internal.events.CSEventCertificateStoreFailed;
import com.io7m.certusine.vanilla.internal.events.CSEventCertificateStored;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType.CSCertificateTaskCompleted;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType.CSCertificateTaskFailedButCanBeRetried;
import com.io7m.jdeferthrow.core.ExceptionTracker;
import io.opentelemetry.api.trace.Span;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.HashSet;
import java.util.Optional;
import java.util.OptionalLong;

import static com.io7m.certusine.vanilla.internal.CSCertificateIO.encodePrivateKey;
import static com.io7m.certusine.vanilla.internal.CSCertificateIO.encodePublicKey;
import static com.io7m.certusine.vanilla.internal.tasks.CSDurations.IO_RETRY_PAUSE_TIME;

/**
 * A task that saves signed certificates.
 */

public final class CSCertificateTaskSignCertificateSaveToOutputs
  extends CSCertificateTaskSignCertificate
{
  private static final Logger LOG =
    LoggerFactory.getLogger(CSCertificateTaskSignCertificateSaveToOutputs.class);

  private final HashSet<String> outputsFailed;

  /**
   * A task that saves signed certificates.
   *
   * @param inContext The task execution context
   */

  public CSCertificateTaskSignCertificateSaveToOutputs(
    final CSCertificateTaskContext inContext)
  {
    super("SignCertificateSaveToOutputs", inContext);

    this.outputsFailed = new HashSet<String>();
  }

  @Override
  CSCertificateTaskStatusType executeActual()
    throws InterruptedException
  {
    LOG.info("saving certificates to outputs");

    final var tracker =
      new ExceptionTracker<IOException>();

    final var context =
      this.context();
    final var domain =
      context.domain();
    final var certificate =
      context.certificate();
    final var keyPair =
      certificate.keyPair();

    try {
      final var storedCertificate =
        context.certificateStore()
          .find(domain.domain(), certificate.name())
          .orElseThrow(() -> {
            return new IllegalStateException(
              "Certificate %s/%s is not present in the local store"
                .formatted(domain.domain(), certificate.name())
            );
          });

      final var outputData =
        new CSCertificateOutputData(
          domain.domain(),
          certificate.name(),
          encodePublicKey(keyPair.getPublic()),
          encodePrivateKey(keyPair.getPrivate()),
          storedCertificate.pemEncodedCertificate(),
          storedCertificate.pemEncodedCertificateFullChain()
        );

      for (final var output : domain.outputs().values()) {
        try {
          LOG.info(
            "saving certificate to output {}:{}",
            output.type(),
            output.name()
          );
          output.write(this.context().telemetry(), outputData);

          context.events()
            .emit(new CSEventCertificateStored(
              domain,
              certificate.name(),
              output.name()
            ));

          this.outputsFailed.remove(output.name());
        } catch (final IOException e) {
          this.outputsFailed.add(output.name());
          tracker.addException(e);
        }
      }
    } catch (final IOException e) {
      tracker.addException(e);
    }

    try {
      tracker.throwIfNecessary();
    } catch (final IOException e) {
      Span.current().recordException(e);
      LOG.error("failed to save certificates to one or more outputs: ", e);
      return new CSCertificateTaskFailedButCanBeRetried(IO_RETRY_PAUSE_TIME, e);
    }

    return new CSCertificateTaskCompleted(
      OptionalLong.empty(),
      Optional.empty()
    );
  }

  @Override
  void executeOnTaskCompletelyFailed()
  {
    final CSCertificateTaskContext context = this.context();
    final var events = context.events();
    for (final var failed : this.outputsFailed) {
      events.emit(new CSEventCertificateStoreFailed(
        context.domain(),
        context.certificate().name(),
        failed
      ));
    }
  }
}
