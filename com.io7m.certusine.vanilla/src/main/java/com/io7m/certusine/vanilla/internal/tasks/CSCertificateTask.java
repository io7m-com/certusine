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

import com.io7m.certusine.api.CSDNSRecordNameType.CSDNSRecordNameAbsolute;
import com.io7m.certusine.api.CSFaultInjectionConfiguration;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType.CSCertificateTaskFailedPermanently;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.StatusCode;
import org.slf4j.MDC;

import java.io.IOException;
import java.util.Objects;

import static com.io7m.certusine.api.CSTelemetryServiceType.recordExceptionAndSetError;

/**
 * The base type of certificate tasks.
 */

public abstract class CSCertificateTask
{
  private final CSCertificateTaskContext context;
  private final String name;
  private int retryAttempts;

  protected CSCertificateTask(
    final String inName,
    final CSCertificateTaskContext inContext)
  {
    this.name =
      Objects.requireNonNull(inName, "inName");
    this.context =
      Objects.requireNonNull(inContext, "context");
    this.retryAttempts = 1;
  }

  protected final CSCertificateTaskContext context()
  {
    return this.context;
  }

  abstract CSCertificateTaskStatusType executeActual()
    throws InterruptedException;

  /**
   * The task has completely failed. Either a previous attempt failed
   * permanently, or the task ran out of retires.
   */

  abstract void executeOnTaskCompletelyFailed();

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
    final var span =
      this.context.telemetry()
        .tracer()
        .spanBuilder(this.name)
        .setAttribute("certusine.attempt", this.retryAttempts)
        .setAttribute("certusine.attemptMax", this.context.retryAttemptsMax())
        .startSpan();

    try (var ignored = span.makeCurrent()) {
      MDC.put("domain", this.context().domain().domain());
      MDC.put("attempt", String.valueOf(this.retryAttempts));
      MDC.put("attemptMax", String.valueOf(this.context.retryAttemptsMax()));

      /*
       * Do any requested fault injection.
       */

      final var faultInjection =
        this.context.options()
          .faultInjection();

      injectCrash(faultInjection);

      if (faultInjection.failTasks()) {
        Span.current().addEvent("InjectedFaultTaskFail");
        return this.onCompletelyFailed(
          span,
          new CSCertificateTaskFailedPermanently(
            new IOException("InjectedFaultTaskFail")
          ));
      }

      if (this.context.retryAttemptsExhausted(this.retryAttempts)) {
        return this.onCompletelyFailed(
          span,
          new CSCertificateTaskFailedPermanently(
            new CSCertificateTaskException(
              this.context().strings().format(
                "errorExceededRetries",
                Integer.valueOf(this.context.retryAttemptsMax())),
              false
            )
          ));
      }

      final var result = this.executeActual();
      if (result.isFailure()) {
        if (result instanceof CSCertificateTaskFailedPermanently) {
          return this.onCompletelyFailed(span, result);
        }
        ++this.retryAttempts;
      } else {
        span.setStatus(StatusCode.OK);
      }
      return result;
    } catch (final Exception e) {
      recordExceptionAndSetError(e);
      return this.context.failedPermanently(e);
    } finally {
      MDC.remove("domain");
      MDC.remove("attempt");
      MDC.remove("attemptMax");
      span.end();
    }
  }

  private CSCertificateTaskStatusType onCompletelyFailed(
    final Span span,
    final CSCertificateTaskStatusType result)
  {
    span.setStatus(StatusCode.ERROR);
    this.executeOnTaskCompletelyFailed();
    return result;
  }

  private static void injectCrash(
    final CSFaultInjectionConfiguration faultInjection)
  {
    if (faultInjection.crashTasks()) {
      Span.current().addEvent("InjectedFaultTaskCrash");
      throw new RuntimeException("Injected I/O exception!");
    }
  }

  /**
   * Determine the TXT record name for the given FQDN.
   *
   * @param fullyQualifiedDomainName The fully-qualified domain name
   *
   * @return The TXT record name
   */

  protected final CSDNSRecordNameAbsolute txtRecordNameToSet(
    final String fullyQualifiedDomainName)
  {
    Objects.requireNonNull(
      fullyQualifiedDomainName,
      "fullyQualifiedDomainName"
    );

    return new CSDNSRecordNameAbsolute(
      "_acme-challenge.%s.".formatted(fullyQualifiedDomainName)
    );
  }

  /**
   * Determine the TXT record (query) name for the given FQDN.
   *
   * @param fullyQualifiedDomainName The fully-qualified domain name
   *
   * @return The TXT record name
   */

  protected final String txtRecordNameToQuery(
    final String fullyQualifiedDomainName)
  {
    return this.txtRecordNameToSet(fullyQualifiedDomainName).name();
  }
}
