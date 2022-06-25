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
import com.io7m.certusine.api.CSDomain;
import com.io7m.certusine.api.CSOptions;
import com.io7m.certusine.certstore.api.CSCertificateStoreType;
import com.io7m.certusine.vanilla.internal.dns.CSDNSQueriesFactoryDJ;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTask;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskAuthorizeDNSInitial;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskContext;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskEnd;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType;
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
  private final CSOptions options;
  private final CSDomain domain;
  private final CSStrings strings;
  private final Clock clock;
  private final CSCertificateStoreType certificateStore;
  private final Function<CSAccount, Session> sessions;

  /**
   * A domain executor.
   *
   * @param inStrings          String resources
   * @param inOptions          The execution options
   * @param inDomain           The executed domain
   * @param inSessions         A provider of ACME sessions
   * @param inClock            The clock used for time-based operations
   * @param inCertificateStore The certificate store
   */

  public CSDomainExecutor(
    final CSStrings inStrings,
    final CSOptions inOptions,
    final CSDomain inDomain,
    final Clock inClock,
    final CSCertificateStoreType inCertificateStore,
    final Function<CSAccount, Session> inSessions)
  {
    this.strings =
      Objects.requireNonNull(inStrings, "strings");
    this.options =
      Objects.requireNonNull(inOptions, "options");
    this.domain =
      Objects.requireNonNull(inDomain, "domain");
    this.clock =
      Objects.requireNonNull(inClock, "inClock");
    this.certificateStore =
      Objects.requireNonNull(inCertificateStore, "inCertificateStore");
    this.sessions =
      Objects.requireNonNull(inSessions, "inSessions");
  }

  /**
   * A domain executor.
   *
   * @param inStrings          String resources
   * @param inOptions          The execution options
   * @param inDomain           The executed domain
   * @param inCertificateStore The certificate store
   * @param inClock            The clock used for time-based operations
   */

  public CSDomainExecutor(
    final CSStrings inStrings,
    final CSOptions inOptions,
    final CSDomain inDomain,
    final Clock inClock,
    final CSCertificateStoreType inCertificateStore)
  {
    this(
      inStrings,
      inOptions,
      inDomain,
      inClock,
      inCertificateStore,
      acmeInformation -> {
        return new Session(acmeInformation.acmeURI());
      }
    );
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

    try {
      final var order =
        account.newOrder()
          .domains(certificate.hosts())
          .create();

      return new CSCertificateTaskAuthorizeDNSInitial(taskContext, order);
    } catch (final AcmeException e) {
      return new CSCertificateTaskEnd(taskContext);
    }
  }

  private static long accumulateDelayRequired(
    final long delayRequired,
    final CSCertificateTaskStatusType status)
  {
    return Math.max(status.delayRequired().orElse(0L), delayRequired);
  }

  private static List<CSCertificateTask> executeTasks(
    final List<CSCertificateTask> tasksNow)
    throws InterruptedException
  {
    LOG.debug("executing tasks");

    final var tasksNext = new ArrayList<CSCertificateTask>(tasksNow.size());
    var delayRequired = 0L;
    for (final var task : tasksNow) {
      final var status = task.execute();
      delayRequired = accumulateDelayRequired(delayRequired, status);

      if (status instanceof CSCertificateTaskCompleted completed) {
        completed.next().ifPresent(tasksNext::add);
      } else if (status instanceof CSCertificateTaskInProgress) {
        tasksNext.add(task);
      } else if (status instanceof CSCertificateTaskFailedPermanently) {
        // ???
      } else if (status instanceof CSCertificateTaskFailedButCanBeRetried) {
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
    final var acmeInfo =
      this.domain.account();

    LOG.debug("executing renewal for domain {}", this.domain.domain());

    final var session =
      this.sessions.apply(acmeInfo);

    final Account account;
    try {
      account = findAccount(session, acmeInfo.accountKeyPair());
    } catch (final AcmeException e) {
      throw new RuntimeException(e);
    }

    final List<CSCertificateTask> tasksInitial =
      new ArrayList<CSCertificateTask>();
    final List<CSCertificateTaskContext> taskContexts =
      new ArrayList<>();

    for (final var certificate : this.domain.certificates().values()) {
      final var context =
        new CSCertificateTaskContext(
          this.strings,
          this.options,
          this.certificateStore,
          this.clock,
          this.domain,
          certificate,
          ATTEMPT_LIMIT,
          new CSDNSQueriesFactoryDJ()
        );

      tasksInitial.add(createCertificateTask(context, account, certificate));
      taskContexts.add(context);
    }

    List<CSCertificateTask> tasksNow = tasksInitial;
    while (true) {
      if (tasksNow.isEmpty()) {
        break;
      }
      tasksNow = executeTasks(tasksNow);
    }

    for (final var taskContext : taskContexts) {
      for (final var dnsRecord : taskContext.dnsRecordsCreated()) {
        try {
          this.domain.dnsConfigurator()
            .deleteTXTRecord(dnsRecord.name(), dnsRecord.value());
        } catch (final IOException e) {
          LOG.error("failed to delete DNS record: ", e);
        }
      }
    }
  }
}
