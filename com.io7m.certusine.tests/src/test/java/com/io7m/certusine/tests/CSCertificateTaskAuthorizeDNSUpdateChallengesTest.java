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
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskAuthorizeDNSUpdateChallenges;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskContext;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType.CSCertificateTaskCompleted;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType.CSCertificateTaskInProgress;
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
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import static com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType.CSCertificateTaskFailedPermanently;
import static java.util.Map.entry;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.shredzone.acme4j.Identifier.TYPE_DNS;

public final class CSCertificateTaskAuthorizeDNSUpdateChallengesTest
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
  private Authorization[] authorizations;
  private Dns01Challenge[] challenges;
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
      new CSCertificate(new CSCertificateName("www"), this.domainKeyPair, List.of("www"));

    this.order =
      Mockito.mock(Order.class);

    this.authorizations = new Authorization[5];
    for (int index = 0; index < this.authorizations.length; ++index) {
      this.authorizations[index] = Mockito.mock(Authorization.class);
    }

    this.challenges = new Dns01Challenge[5];
    for (int index = 0; index < this.authorizations.length; ++index) {
      this.challenges[index] = Mockito.mock(Dns01Challenge.class);
    }

    for (int index = 0; index < this.authorizations.length; ++index) {
      Mockito.when(this.challenges[index].getDigest())
        .thenReturn("YW1vbmdzdCB0aGUgbGVhdmVzCg==");
      Mockito.when(this.authorizations[index].findChallenge(Dns01Challenge.TYPE))
        .thenReturn(this.challenges[index]);
      Mockito.when(this.authorizations[index].getExpires())
        .thenReturn(Instant.now(Clock.systemUTC()).plus(Duration.ofHours(1L)));
      Mockito.when(this.authorizations[index].getIdentifier())
        .thenReturn(new Identifier(TYPE_DNS, "example.com"));
    }

    Mockito.when(this.order.getAuthorizations())
      .thenReturn(List.of(this.authorizations));
  }

  /**
   * Pending challenges that eventually become valid cause success.
   *
   * @throws Exception On errors
   */

  @Test
  public void testPendingChallengesBecomeValid()
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

    for (int index = 0; index < this.authorizations.length; ++index) {
      Mockito.when(this.challenges[index].getStatus())
        .thenReturn(Status.PENDING);
    }

    final var task =
      new CSCertificateTaskAuthorizeDNSUpdateChallenges(context, this.order);

    for (int index = 0; index < 5; ++index) {
      final var status = (CSCertificateTaskInProgress) task.execute();
    }

    for (int index = 0; index < this.authorizations.length; ++index) {
      Mockito.when(this.challenges[index].getStatus())
        .thenReturn(Status.VALID);
    }

    final var status = (CSCertificateTaskCompleted) task.execute();

    final var dnsRequests = this.dns.requests();
    assertEquals(0, dnsRequests.size());
  }

  /**
   * Pending challenges that eventually become invalid cause failure.
   *
   * @throws Exception On errors
   */

  @Test
  public void testPendingChallengesBecomeInvalid()
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

    for (int index = 0; index < this.authorizations.length; ++index) {
      Mockito.when(this.challenges[index].getStatus())
        .thenReturn(Status.PENDING);
    }

    final var task =
      new CSCertificateTaskAuthorizeDNSUpdateChallenges(context, this.order);

    for (int index = 0; index < 5; ++index) {
      final var status = (CSCertificateTaskInProgress) task.execute();
      assertEquals(5_000L, status.delayRequired().orElseThrow());
    }

    for (int index = 0; index < this.authorizations.length; ++index) {
      Mockito.when(this.challenges[index].getStatus())
        .thenReturn(Status.INVALID);
    }

    final var status = (CSCertificateTaskFailedPermanently) task.execute();

    final var dnsRequests = this.dns.requests();
    assertEquals(0, dnsRequests.size());
  }
}
