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
import com.io7m.certusine.vanilla.internal.CSStrings;
import com.io7m.certusine.vanilla.internal.dns.CSDNSQueriesFactoryDJ;
import com.io7m.certusine.vanilla.internal.events.CSEventServiceType;
import com.io7m.certusine.vanilla.internal.store.CSCertificateStoreServiceType;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTask;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskAuthorizeDNSTriggerChallenges;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskAuthorizeDNSUpdateChallenges;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskContext;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType.CSCertificateTaskCompleted;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.mockito.internal.verification.Times;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Identifier;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Problem;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.toolbox.JSON;

import java.net.URI;
import java.net.URL;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;

import static com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType.CSCertificateTaskFailedPermanently;
import static java.util.Map.entry;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.shredzone.acme4j.Identifier.TYPE_DNS;

public final class CSCertificateTaskAuthorizeDNSTriggerChallengesTest
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
  private CSCertificateStoreServiceType certificateStores;

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
    this.certificateStores =
      Mockito.mock(CSCertificateStoreServiceType.class);
    Mockito.when(this.certificateStores.store())
      .thenReturn(this.certificates);

    this.account =
      new CSAccount(this.accountKeyPair, URI.create("http://localhost:20000"));
    this.certificate0 =
      new CSCertificate(
        new CSCertificateName("www"),
        this.domainKeyPair,
        List.of("www"));

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
   * An authorization in the correct state causes challenges to be triggered.
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
        Mockito.mock(CSEventServiceType.class),
        CSTelemetryNoOp.noop(),
        this.options,
        this.certificateStores,
        this.clock,
        domain,
        this.certificate0,
        3,
        new CSDNSQueriesFactoryDJ()
      );

    Mockito.when(this.challenge0.getStatus())
      .thenReturn(Status.PENDING);

    final var task =
      new CSCertificateTaskAuthorizeDNSTriggerChallenges(context, this.order);

    final var status = (CSCertificateTaskCompleted) task.execute();
    assertEquals(OptionalLong.empty(), status.delayRequired());
    assertEquals(
      CSCertificateTaskAuthorizeDNSUpdateChallenges.class,
      status.next().map(CSCertificateTask::getClass).orElseThrow()
    );

    Mockito.verify(this.challenge0, new Times(1))
      .trigger();

    final var dnsRequests = this.dns.requests();
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
        Mockito.mock(CSEventServiceType.class),
        CSTelemetryNoOp.noop(),
        this.options,
        this.certificateStores,
        this.clock,
        domain,
        this.certificate0,
        3,
        new CSDNSQueriesFactoryDJ()
      );

    Mockito.when(this.challenge0.getStatus())
      .thenReturn(Status.VALID);

    final var task =
      new CSCertificateTaskAuthorizeDNSTriggerChallenges(context, this.order);

    final var status = (CSCertificateTaskCompleted) task.execute();
    assertEquals(OptionalLong.empty(), status.delayRequired());
    assertEquals(
      CSCertificateTaskAuthorizeDNSUpdateChallenges.class,
      status.next().map(CSCertificateTask::getClass).orElseThrow()
    );

    Mockito.verify(this.challenge0, new Times(0))
      .trigger();

    final var dnsRequests = this.dns.requests();
    assertEquals(0, dnsRequests.size());
  }

  /**
   * An authorization that's invalid causes a permanent failure.
   *
   * @throws Exception On errors
   */

  @Test
  public void testAuthorizationInvalid()
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
        this.certificateStores,
        this.clock,
        domain,
        this.certificate0,
        3,
        new CSDNSQueriesFactoryDJ()
      );

    Mockito.when(this.challenge0.getStatus())
      .thenReturn(Status.INVALID);

    final var task =
      new CSCertificateTaskAuthorizeDNSTriggerChallenges(context, this.order);

    final var status =
      (CSCertificateTaskFailedPermanently) task.execute();

    Mockito.verify(this.challenge0, new Times(0))
      .trigger();

    final var dnsRequests = this.dns.requests();
    assertEquals(0, dnsRequests.size());
  }

  /**
   * An authorization that's invalid causes a permanent failure.
   *
   * @throws Exception On errors
   */

  @Test
  public void testAuthorizationInvalidWithErrorReport()
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
        this.certificateStores,
        this.clock,
        domain,
        this.certificate0,
        3,
        new CSDNSQueriesFactoryDJ()
      );

    Mockito.when(this.challenge0.getStatus())
      .thenReturn(Status.INVALID);
    Mockito.when(this.order.getError())
      .thenReturn(new Problem(
        JSON.parse(
          """
            {
               "title": "Everything Failed"
            }
            """),
        new URL("http://localhost:20000/")
      ));

    final var task =
      new CSCertificateTaskAuthorizeDNSTriggerChallenges(context, this.order);

    final var status =
      (CSCertificateTaskFailedPermanently) task.execute();

    Mockito.verify(this.challenge0, new Times(0))
      .trigger();

    final var dnsRequests = this.dns.requests();
    assertEquals(0, dnsRequests.size());
  }
}
