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
import com.io7m.certusine.api.CSOptions;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTask;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskAuthorizeDNSCheckRecords;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskAuthorizeDNSInitial;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskContext;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskException;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskSignCertificateInitial;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType.CSCertificateTaskCompleted;
import com.io7m.certusine.vanilla.internal.dns.CSDNSQueriesFactoryDJ;
import com.io7m.certusine.vanilla.internal.CSStrings;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Identifier;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Dns01Challenge;

import java.net.URI;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.OptionalLong;

import static com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType.*;
import static java.util.Map.entry;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.shredzone.acme4j.Identifier.TYPE_DNS;

public final class CSCertificateTaskAuthorizeDNSInitialTest
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
  private Authorization authorization0;
  private Dns01Challenge challenge0;
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
      new CSOptions(this.file, Duration.ofSeconds(1L), Duration.ofDays(1L));
    this.dns =
      new CSFakeDNSConfigurator();
    this.output =
      new CSFakeCertificateOutput();
    this.certificates =
      new CSFakeCertificateStore();

    this.account =
      new CSAccount(this.accountKeyPair, URI.create("http://localhost:20000"));
    this.certificate0 =
      new CSCertificate(new CSCertificateName("www"), this.domainKeyPair, List.of("www"));

    this.order =
      Mockito.mock(Order.class);
    this.authorization0 =
      Mockito.mock(Authorization.class);
    this.challenge0 =
      Mockito.mock(Dns01Challenge.class);

    Mockito.when(this.challenge0.getDigest())
      .thenReturn("YW1vbmdzdCB0aGUgbGVhdmVzCg==");
    Mockito.when(this.authorization0.findChallenge(Dns01Challenge.TYPE))
      .thenReturn(this.challenge0);
    Mockito.when(this.authorization0.getExpires())
      .thenReturn(Instant.now(Clock.systemUTC()).plus(Duration.ofHours(1L)));
    Mockito.when(this.authorization0.getIdentifier())
      .thenReturn(new Identifier(TYPE_DNS, "example.com"));
    Mockito.when(this.order.getAuthorizations())
      .thenReturn(List.of(this.authorization0));
  }

  /**
   * An authorization in the correct state causes DNS records to be created.
   *
   * @throws Exception On errors
   */

  @Test
  public void testAuthorizationStarted()
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
        this.options,
        this.certificates,
        this.clock,
        domain,
        this.certificate0,
        3,
        new CSDNSQueriesFactoryDJ()
      );

    Mockito.when(this.authorization0.getStatus())
      .thenReturn(Status.READY);

    final var task =
      new CSCertificateTaskAuthorizeDNSInitial(context, this.order);

    this.clock.times.add(
      OffsetDateTime.parse("2000-01-01T00:00:00+00:00")
        .toInstant()
    );

    final var status = (CSCertificateTaskCompleted) task.execute();
    assertEquals(
      this.options.dnsWaitTime().toMillis(),
      status.delayRequired().getAsLong()
    );
    assertEquals(
      CSCertificateTaskAuthorizeDNSCheckRecords.class,
      status.next().map(CSCertificateTask::getClass).orElseThrow()
    );

    final var dnsRequests = this.dns.requests();
    assertEquals("CREATE _acme-challenge.example.com.", dnsRequests.poll());
    assertEquals(0, dnsRequests.size());
  }

  /**
   * An authorization that's already valid causes a request for certificate
   * signing.
   *
   * @throws Exception On errors
   */

  @Test
  public void testAuthorizationAlreadyValid()
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
        this.options,
        this.certificates,
        this.clock,
        domain,
        this.certificate0,
        3,
        new CSDNSQueriesFactoryDJ()
      );

    Mockito.when(this.authorization0.getStatus())
      .thenReturn(Status.VALID);

    final var task =
      new CSCertificateTaskAuthorizeDNSInitial(context, this.order);

    final var status = (CSCertificateTaskCompleted) task.execute();
    assertEquals(OptionalLong.empty(), status.delayRequired());
    assertEquals(
      CSCertificateTaskSignCertificateInitial.class,
      status.next().map(CSCertificateTask::getClass).orElseThrow()
    );

    final var dnsRequests = this.dns.requests();
    assertEquals(0, dnsRequests.size());
  }

  /**
   * A failing DNS server results in retries.
   *
   * @throws Exception On errors
   */

  @Test
  public void testDNSRetry()
    throws Exception
  {
    final var dnsCrashing =
      new CSFakeDNSConfiguratorCrashing();

    final var domain =
      new CSDomain(
        this.account,
        "example.com",
        Map.ofEntries(entry("www", this.certificate0)),
        dnsCrashing,
        Map.ofEntries(entry("out", this.output))
      );

    final var context =
      new CSCertificateTaskContext(
        this.strings,
        this.options,
        this.certificates,
        this.clock,
        domain,
        this.certificate0,
        3,
        new CSDNSQueriesFactoryDJ()
      );

    Mockito.when(this.authorization0.getStatus())
      .thenReturn(Status.READY);

    final var task =
      new CSCertificateTaskAuthorizeDNSInitial(context, this.order);

    {
      final var status =
        (CSCertificateTaskFailedButCanBeRetried) task.execute();
      assertEquals(CSCertificateTaskException.class, status.exception().getClass());
    }

    {
      final var status =
        (CSCertificateTaskFailedButCanBeRetried) task.execute();
      assertEquals(CSCertificateTaskException.class, status.exception().getClass());
    }

    {
      final var status =
        (CSCertificateTaskFailedButCanBeRetried) task.execute();
      assertEquals(CSCertificateTaskException.class, status.exception().getClass());
    }

    {
      final var status =
        (CSCertificateTaskFailedPermanently) task.execute();
      assertEquals(CSCertificateTaskException.class, status.exception().getClass());
    }

    final var dnsRequests = dnsCrashing.requests();
    assertEquals("CREATE _acme-challenge.example.com.", dnsRequests.poll());
    assertEquals("CREATE _acme-challenge.example.com.", dnsRequests.poll());
    assertEquals("CREATE _acme-challenge.example.com.", dnsRequests.poll());
    assertEquals(0, dnsRequests.size());
  }

  /**
   * The ACME server fails to present a DNS challenge.
   *
   * @throws Exception On errors
   */

  @Test
  public void testNoAcmeDNSChallenge()
    throws Exception
  {
    final var dnsCrashing =
      new CSFakeDNSConfiguratorCrashing();

    final var domain =
      new CSDomain(
        this.account,
        "example.com",
        Map.ofEntries(entry("www", this.certificate0)),
        dnsCrashing,
        Map.ofEntries(entry("out", this.output))
      );

    final var context =
      new CSCertificateTaskContext(
        this.strings,
        this.options,
        this.certificates,
        this.clock,
        domain,
        this.certificate0,
        3,
        new CSDNSQueriesFactoryDJ()
      );

    Mockito.when(this.authorization0.findChallenge(Dns01Challenge.TYPE))
      .thenReturn(null);
    Mockito.when(this.authorization0.getStatus())
      .thenReturn(Status.READY);

    final var task =
      new CSCertificateTaskAuthorizeDNSInitial(context, this.order);

    {
      final var status =
        (CSCertificateTaskFailedPermanently) task.execute();
      assertEquals(CSCertificateTaskException.class, status.exception().getClass());
    }

    final var dnsRequests = dnsCrashing.requests();
    assertEquals(0, dnsRequests.size());
  }
}
