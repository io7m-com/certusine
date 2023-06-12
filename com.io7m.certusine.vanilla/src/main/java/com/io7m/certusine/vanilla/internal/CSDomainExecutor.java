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

package com.io7m.certusine.vanilla.internal;

import com.io7m.certusine.api.CSAccount;
import com.io7m.certusine.api.CSCertificate;
import com.io7m.certusine.api.CSConfigurationServiceType;
import com.io7m.certusine.api.CSDNSRecordNameType;
import com.io7m.certusine.api.CSDNSRecordNameType.CSDNSRecordNameAbsolute;
import com.io7m.certusine.api.CSDNSRecordNameType.CSDNSRecordNameRelative;
import com.io7m.certusine.api.CSDomain;
import com.io7m.certusine.api.CSTelemetryServiceType;
import com.io7m.certusine.vanilla.internal.dns.CSDNSQueriesFactoryDJ;
import com.io7m.certusine.vanilla.internal.events.CSEventCertificateRenewalFailed;
import com.io7m.certusine.vanilla.internal.events.CSEventServiceType;
import com.io7m.certusine.vanilla.internal.store.CSCertificateStoreServiceType;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTask;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskAuthorizeDNSInitial;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskContext;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskEnd;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType;
import io.opentelemetry.api.trace.StatusCode;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.exception.AcmeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.KeyPair;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;

import static com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType.CSCertificateTaskCompleted;
import static com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType.CSCertificateTaskFailedButCanBeRetried;
import static com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType.CSCertificateTaskFailedPermanently;
import static com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType.CSCertificateTaskInProgress;

/**
 * A domain executor.
 */

public final class CSDomainExecutor
{
  private static final Logger LOG =
    LoggerFactory.getLogger(CSDomainExecutor.class);

  private static final int ATTEMPT_LIMIT = 10;

  private final CSDomain domain;
  private final CSStrings strings;
  private final Clock clock;
  private final Function<CSAccount, Session> sessions;
  private final CSTelemetryServiceType telemetry;
  private final CSEventServiceType events;
  private final CSConfigurationServiceType configs;
  private final CSCertificateStoreServiceType certificateStores;

  /**
   * A domain executor.
   *
   * @param inStrings           String resources
   * @param inConfigs           The configuration service
   * @param inTelemetry         A telemetry service
   * @param inEvents            The event service
   * @param inCertificateStores The certificate stores
   * @param inDomain            The executed domain
   * @param inClock             The clock used for time-based operations
   * @param inSessions          A provider of ACME sessions
   */

  public CSDomainExecutor(
    final CSStrings inStrings,
    final CSTelemetryServiceType inTelemetry,
    final CSEventServiceType inEvents,
    final CSConfigurationServiceType inConfigs,
    final CSCertificateStoreServiceType inCertificateStores,
    final CSDomain inDomain,
    final Clock inClock,
    final Function<CSAccount, Session> inSessions)
  {
    this.strings =
      Objects.requireNonNull(inStrings, "strings");
    this.telemetry =
      Objects.requireNonNull(inTelemetry, "inTelemetry");
    this.events =
      Objects.requireNonNull(inEvents, "inEvents");
    this.configs =
      Objects.requireNonNull(inConfigs, "configs");
    this.certificateStores =
      Objects.requireNonNull(inCertificateStores, "certificateStores");
    this.domain =
      Objects.requireNonNull(inDomain, "domain");
    this.clock =
      Objects.requireNonNull(inClock, "inClock");
    this.sessions =
      Objects.requireNonNull(inSessions, "inSessions");
  }

  private static Account findAccount(
    final Session session,
    final KeyPair accountKey)
    throws AcmeException
  {
    LOG.debug("locating account");
    return new AccountBuilder()
      .agreeToTermsOfService()
      .useKeyPair(accountKey)
      .create(session);
  }

  private static CSCertificateTask createCertificateTask(
    final CSCertificateTaskContext taskContext,
    final Account account,
    final CSCertificate certificate)
  {
    LOG.debug("creating certificate task for {}", certificate.name());

    final var span =
      taskContext.telemetry()
        .tracer()
        .spanBuilder("CreateCertificateTask")
        .setAttribute("certusine.certificate", certificate.name().value())
        .startSpan();

    try (var ignored = span.makeCurrent()) {
      final var fullyQualifiedDomainNames =
        certificate.fullyQualifiedHostNames(taskContext.domain());

      try {
        final var order =
          account.newOrder()
            .domains(fullyQualifiedDomainNames)
            .create();

        return new CSCertificateTaskAuthorizeDNSInitial(taskContext, order);
      } catch (final AcmeException e) {
        span.recordException(e);
        return new CSCertificateTaskEnd(taskContext);
      }
    } catch (final Exception e) {
      span.recordException(e);
      throw e;
    } finally {
      span.end();
    }
  }

  private static long accumulateDelayRequired(
    final long delayRequired,
    final CSCertificateTaskStatusType status)
  {
    return Math.max(status.delayRequired().orElse(0L), delayRequired);
  }

  private List<CSCertificateTask> executeTasks(
    final List<CSCertificateTask> tasksNow)
    throws InterruptedException
  {
    LOG.debug("executing tasks");

    final var taskExec =
      this.telemetry.meter()
        .counterBuilder("certusine_tasks_executed")
        .setDescription("Certificate tasks that executed.")
        .build();

    final var taskOk =
      this.telemetry.meter()
        .counterBuilder("certusine_tasks_succeeded")
        .setDescription("Certificate tasks that executed and succeeded.")
        .build();

    final var taskFailed =
      this.telemetry.meter()
        .counterBuilder("certusine_tasks_failed")
        .setDescription("Certificate tasks that executed and failed.")
        .build();

    final var taskRetry =
      this.telemetry.meter()
        .counterBuilder("certusine_tasks_retried")
        .setDescription("Certificate tasks that had to be retried.")
        .build();

    final var tasksNext = new ArrayList<CSCertificateTask>(tasksNow.size());
    var delayRequired = 0L;
    for (final var task : tasksNow) {
      final var status = task.execute();

      delayRequired = accumulateDelayRequired(delayRequired, status);

      if (status instanceof final CSCertificateTaskCompleted completed) {
        completed.next().ifPresent(tasksNext::add);
        taskOk.add(1L);
        taskExec.add(1L);
      } else if (status instanceof CSCertificateTaskInProgress) {
        tasksNext.add(task);
      } else if (status instanceof CSCertificateTaskFailedPermanently) {
        taskFailed.add(1L);
        taskExec.add(1L);
      } else if (status instanceof CSCertificateTaskFailedButCanBeRetried) {
        taskRetry.add(1L);
        taskExec.add(1L);
        tasksNext.add(task);
      }
    }

    LOG.debug(
      "pausing for {} ms before continuing tasks",
      Long.valueOf(delayRequired)
    );
    Thread.sleep(delayRequired);
    return tasksNext;
  }

  /**
   * Execute the domain.
   */

  public void execute()
    throws InterruptedException
  {
    final var span =
      this.telemetry.tracer()
        .spanBuilder("Domain")
        .setAttribute("certusine.domain", this.domain.domain())
        .startSpan();

    try (var ignored = span.makeCurrent()) {
      this.executeInSpan();
    } catch (final Throwable ex) {
      span.setStatus(StatusCode.ERROR);
      span.recordException(ex);
      throw ex;
    } finally {
      span.end();
    }
  }

  private void executeInSpan()
    throws InterruptedException
  {
    final var acmeInfo =
      this.domain.account();

    LOG.debug("executing renewal for domain {}", this.domain.domain());

    final var account =
      this.executeOpenAccount(acmeInfo);
    final var taskContexts =
      this.executeDomainTasks(account);

    this.executeCleanUpDNSRecords(taskContexts);
  }

  private List<CSCertificateTaskContext> executeDomainTasks(
    final Account account)
  {
    final var span =
      this.telemetry.tracer()
        .spanBuilder("ExecuteDomainTasks")
        .startSpan();

    final List<CSCertificateTask> tasksInitial =
      new ArrayList<>();
    final List<CSCertificateTaskContext> taskContexts =
      new ArrayList<>();

    final var options =
      this.configs.configuration()
        .options();

    try (var ignored = span.makeCurrent()) {
      for (final var certificate : this.domain.certificates().values()) {

        final var context =
          new CSCertificateTaskContext(
            this.strings,
            this.events,
            this.telemetry,
            options,
            this.certificateStores,
            this.clock,
            this.domain,
            certificate,
            ATTEMPT_LIMIT,
            new CSDNSQueriesFactoryDJ()
          );

        tasksInitial.add(createCertificateTask(context, account, certificate));
        taskContexts.add(context);
      }

      var tasksNow = tasksInitial;
      while (true) {
        if (tasksNow.isEmpty()) {
          break;
        }
        tasksNow = this.executeTasks(tasksNow);
      }

      return taskContexts;
    } catch (final Exception e) {
      span.setStatus(StatusCode.ERROR);
      span.recordException(e);
      return taskContexts;
    } finally {
      this.publishTaskContextFailures(taskContexts);
      span.end();
    }
  }

  private void publishTaskContextFailures(
    final List<CSCertificateTaskContext> taskContexts)
  {
    for (final var context : taskContexts) {
      if (context.isFailed()) {
        this.events.emit(
          new CSEventCertificateRenewalFailed(
            this.domain,
            context.certificate().name()
          )
        );
      }
    }
  }

  private Account executeOpenAccount(
    final CSAccount acmeInfo)
  {
    final var span =
      this.telemetry.tracer()
        .spanBuilder("OpenAccount")
        .startSpan();

    try (var ignored = span.makeCurrent()) {
      final var session =
        this.sessions.apply(acmeInfo);

      final Account account;
      try {
        account = findAccount(session, acmeInfo.accountKeyPair());
      } catch (final AcmeException e) {
        throw new RuntimeException(e);
      }
      return account;
    } finally {
      span.end();
    }
  }

  private void executeCleanUpDNSRecords(
    final List<CSCertificateTaskContext> taskContexts)
    throws InterruptedException
  {
    final var span =
      this.telemetry.tracer()
        .spanBuilder("DNSCleanup")
        .startSpan();

    try (var ignored = span.makeCurrent()) {
      for (final var taskContext : taskContexts) {
        for (final var dnsRecord : taskContext.dnsRecordsCreated()) {
          try {
            final CSDNSRecordNameType name;
            if (dnsRecord.name().endsWith(".")) {
              name = new CSDNSRecordNameAbsolute(dnsRecord.name());
            } else {
              name = new CSDNSRecordNameRelative(dnsRecord.name());
            }

            this.domain.dnsConfigurator()
              .deleteTXTRecord(this.telemetry, name, dnsRecord.value());
          } catch (final IOException e) {
            LOG.error("failed to delete DNS record: ", e);
          }
        }
      }
    } finally {
      span.end();
    }
  }
}
