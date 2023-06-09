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


package com.io7m.certusine.tests;

import com.io7m.certusine.api.CSAccount;
import com.io7m.certusine.api.CSCertificate;
import com.io7m.certusine.api.CSCertificateName;
import com.io7m.certusine.api.CSDomain;
import com.io7m.certusine.api.CSFaultInjectionConfiguration;
import com.io7m.certusine.api.CSOptions;
import com.io7m.certusine.api.CSTelemetryNoOp;
import com.io7m.certusine.certstore.api.CSCertificateStored;
import com.io7m.certusine.vanilla.internal.CSStrings;
import com.io7m.certusine.vanilla.internal.events.CSEventServiceType;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTask;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskContext;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskSignCertificateInitial;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskSignCertificateSaveToOutputs;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskSignCertificateUpdate;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType.CSCertificateTaskCompleted;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType.CSCertificateTaskFailedPermanently;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.exception.AcmeException;

import java.net.URI;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;

import static java.util.Map.entry;
import static org.junit.jupiter.api.Assertions.assertEquals;

public final class CSCertificateTaskSignCertificateInitialTest
{
  private CSStrings strings;
  private CSOptions options;
  private KeyPair accountKeyPair;
  private KeyPair domainKeyPair;
  private CSFakeDNSConfigurator dns;
  private CSFakeCertificateOutput output;
  private CSCertificate certificate0;
  private CSAccount account;
  private Order order;
  private CSFakeDNSQueriesFactory dnsQueryFactory;
  private CSFakeDNSQueries dnsQuery;
  private Path directory;
  private Path file;
  private CSFakeCertificateStore certificates;
  private CSFakeClock clock;

  private static KeyPair generateKeyPair()
    throws Exception
  {
    final var parameterSpec =
      new ECGenParameterSpec("secp384r1");
    final var generator =
      KeyPairGenerator.getInstance("EC");

    generator.initialize(parameterSpec, new SecureRandom());
    return generator.generateKeyPair();
  }

  @BeforeEach
  public void setup()
    throws Exception
  {
    this.directory =
      CSTestDirectories.createTempDirectory();
    this.file =
      this.directory.resolve("store.db");

    this.clock =
      new CSFakeClock();
    this.accountKeyPair =
      generateKeyPair();
    this.domainKeyPair =
      generateKeyPair();
    this.strings =
      new CSStrings(Locale.getDefault());
    this.options =
      new CSOptions(
        this.file,
        Duration.ofSeconds(1L),
        Duration.ofDays(1L),
        Optional.empty(),
        CSFaultInjectionConfiguration.disabled()
      );
    this.dns =
      new CSFakeDNSConfigurator();
    this.output =
      new CSFakeCertificateOutput();
    this.certificates =
      new CSFakeCertificateStore();

    this.account =
      new CSAccount(this.accountKeyPair, URI.create("http://localhost:20000"));
    this.certificate0 =
      new CSCertificate(
        new CSCertificateName("www"),
        this.domainKeyPair,
        List.of("www"));

    this.order =
      Mockito.mock(Order.class);
    this.dnsQuery =
      new CSFakeDNSQueries();
    this.dnsQueryFactory =
      new CSFakeDNSQueriesFactory(s -> this.dnsQuery);
  }

  /**
   * If the certificate exists but is not due to expire, then no signing request
   * proceeds.
   *
   * @throws Exception On errors
   */

  @Test
  public void testCertificateNotExpiringSoon()
    throws Exception
  {
    final var domain =
      new CSDomain(
        this.account,
        "example.com",
        Map.ofEntries(entry("www", this.certificate0)),
        this.dns,
        Map.ofEntries(entry("out", this.output))
      );

    final var context =
      new CSCertificateTaskContext(
        this.strings,
        Mockito.mock(CSEventServiceType.class),
        CSTelemetryNoOp.noop(),
        this.options,
        this.certificates,
        this.clock,
        domain,
        this.certificate0,
        3,
        this.dnsQueryFactory
      );

    /*
     * It's 1990...
     */

    this.clock.times.add(
      OffsetDateTime.parse("1990-01-01T00:00:00+00:00").toInstant()
    );

    /*
     * The certificate expires in 2000...
     */

    this.certificates.put(
      new CSCertificateStored(
        "example.com",
        new CSCertificateName("www"),
        OffsetDateTime.parse("2000-01-01T00:00:00+00:00"),
        OffsetDateTime.parse("2000-01-01T00:00:00+00:00"),
        "-- BEGIN CERTIFICATE --",
        "-- BEGIN CERTIFICATE --"
      )
    );

    final var task =
      new CSCertificateTaskSignCertificateInitial(context, this.order);

    final var status = (CSCertificateTaskCompleted) task.execute();
    assertEquals(OptionalLong.empty(), status.delayRequired());
    assertEquals(
      CSCertificateTaskSignCertificateSaveToOutputs.class,
      status.next().map(CSCertificateTask::getClass).orElseThrow()
    );

    final var dnsRequests = this.dns.requests();
    assertEquals(0, dnsRequests.size());
  }

  /**
   * If the certificate does not exist, then signing proceeds.
   *
   * @throws Exception On errors
   */

  @Test
  public void testCertificateNonexistent()
    throws Exception
  {
    final var domain =
      new CSDomain(
        this.account,
        "example.com",
        Map.ofEntries(entry("www", this.certificate0)),
        this.dns,
        Map.ofEntries(entry("out", this.output))
      );

    final var context =
      new CSCertificateTaskContext(
        this.strings,
        Mockito.mock(CSEventServiceType.class),
        CSTelemetryNoOp.noop(),
        this.options,
        this.certificates,
        this.clock,
        domain,
        this.certificate0,
        3,
        this.dnsQueryFactory
      );

    /*
     * It's 1990...
     */

    this.clock.times.add(
      OffsetDateTime.parse("1990-01-01T00:00:00+00:00").toInstant()
    );

    final var task =
      new CSCertificateTaskSignCertificateInitial(context, this.order);

    final var status = (CSCertificateTaskCompleted) task.execute();
    assertEquals(OptionalLong.of(5_000L), status.delayRequired());
    assertEquals(
      CSCertificateTaskSignCertificateUpdate.class,
      status.next().map(CSCertificateTask::getClass).orElseThrow()
    );

    final var dnsRequests = this.dns.requests();
    assertEquals(0, dnsRequests.size());
  }

  /**
   * If the certificate exists but isn't near expiring, then nothing happens.
   *
   * @throws Exception On errors
   */

  @Test
  public void testCertificateExistsNotOldEnough()
    throws Exception
  {
    final var domain =
      new CSDomain(
        this.account,
        "example.com",
        Map.ofEntries(entry("www", this.certificate0)),
        this.dns,
        Map.ofEntries(entry("out", this.output))
      );

    final var context =
      new CSCertificateTaskContext(
        this.strings,
        Mockito.mock(CSEventServiceType.class),
        CSTelemetryNoOp.noop(),
        this.options,
        this.certificates,
        this.clock,
        domain,
        this.certificate0,
        3,
        this.dnsQueryFactory
      );

    /*
     * It's 1990...
     */

    this.clock.times.add(
      OffsetDateTime.parse("1990-01-01T00:00:00+00:00").toInstant()
    );

    /*
     * The certificate expires tomorrow...
     */

    this.certificates.put(
      new CSCertificateStored(
        "example.com",
        new CSCertificateName("www"),
        OffsetDateTime.parse("1990-01-01T00:00:00+00:00"),
        OffsetDateTime.parse("1990-01-02T00:00:00+00:00"),
        "-- BEGIN CERTIFICATE --",
        "-- BEGIN CERTIFICATE --"
      )
    );

    final var task =
      new CSCertificateTaskSignCertificateInitial(context, this.order);

    final var status = (CSCertificateTaskCompleted) task.execute();
    assertEquals(OptionalLong.of(5_000L), status.delayRequired());
    assertEquals(
      CSCertificateTaskSignCertificateUpdate.class,
      status.next().map(CSCertificateTask::getClass).orElseThrow()
    );

    final var dnsRequests = this.dns.requests();
    assertEquals(0, dnsRequests.size());
  }

  /**
   * Signing proceeds, but the ACME server explodes.
   *
   * @throws Exception On errors
   */

  @Test
  public void testCertificateSignButServerProblem()
    throws Exception
  {
    final var domain =
      new CSDomain(
        this.account,
        "example.com",
        Map.ofEntries(entry("www", this.certificate0)),
        this.dns,
        Map.ofEntries(entry("out", this.output))
      );

    final var context =
      new CSCertificateTaskContext(
        this.strings,
        Mockito.mock(CSEventServiceType.class),
        CSTelemetryNoOp.noop(),
        this.options,
        this.certificates,
        this.clock,
        domain,
        this.certificate0,
        3,
        this.dnsQueryFactory
      );

    /*
     * It's 1990...
     */

    this.clock.times.add(
      OffsetDateTime.parse("1990-01-01T00:00:00+00:00").toInstant()
    );

    Mockito.doThrow(new AcmeException())
      .when(this.order)
      .execute(Mockito.any());

    final var task =
      new CSCertificateTaskSignCertificateInitial(context, this.order);

    final var status = (CSCertificateTaskFailedPermanently) task.execute();

    final var dnsRequests = this.dns.requests();
    assertEquals(0, dnsRequests.size());
  }
}
