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

import org.slf4j.MDC;

import java.util.Objects;

/**
 * The base type of certificate tasks.
 */

public abstract class CSCertificateTask
{
  private final CSCertificateTaskContext context;
  private int retryAttempts;

  protected CSCertificateTask(
    final CSCertificateTaskContext inContext)
  {
    this.context = Objects.requireNonNull(inContext, "context");
    this.retryAttempts = 1;
  }

  protected final CSCertificateTaskContext context()
  {
    return this.context;
  }

  abstract CSCertificateTaskStatusType executeActual()
    throws InterruptedException;

  /**
   * Execute the task, tracking the number of retries on failure.
   *
   * @return The task result
   *
   * @throws InterruptedException If the task is interrupted
   */

  public final CSCertificateTaskStatusType execute()
    throws InterruptedException
  {
    try {
      MDC.put("domain", this.context().domain().domain());
      MDC.put("attempt", String.valueOf(this.retryAttempts));
      MDC.put("attemptMax", String.valueOf(this.context.retryAttemptsMax()));

      if (this.context.retryAttemptsExhausted(this.retryAttempts)) {
        return new CSCertificateTaskStatusType.CSCertificateTaskFailedPermanently(
          new CSCertificateTaskException(
            this.context().strings().format(
              "errorExceededRetries",
              Integer.valueOf(this.context.retryAttemptsMax())),
            false
          )
        );
      }

      final var result = this.executeActual();
      if (result.isFailure()) {
        ++this.retryAttempts;
      }
      return result;
    } finally {
      MDC.remove("domain");
      MDC.remove("attempt");
      MDC.remove("attemptMax");
    }
  }
}
