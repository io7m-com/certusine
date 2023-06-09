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
import com.io7m.certusine.vanilla.internal.CSDomainExecutor;
import com.io7m.certusine.vanilla.internal.CSStrings;
import com.io7m.certusine.vanilla.internal.events.CSEventServiceType;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.shredzone.acme4j.Session;

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

import static org.junit.jupiter.api.Assertions.assertEquals;

public final class CSDomainExecutorTests
{
  private KeyPair accountKeyPair;
  private KeyPair domainKeyPair;
  private CSFakeDNSConfigurator dnsConfigurator;
  private CSFakeCertificateOutput output0;
  private CSFakeCertificateOutput output1;
  private CSFakeCertificateOutput output2;
  private CSStrings strings;
  private CSFakeAcmeProvider acmeProvider;
  private CSFakeAcmeServer acmeServer;
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
    this.certificates =
      new CSFakeCertificateStore();

    this.accountKeyPair =
      generateKeyPair();
    this.domainKeyPair =
      generateKeyPair();

    this.dnsConfigurator =
      new CSFakeDNSConfigurator();

    this.output0 =
      new CSFakeCertificateOutput();
    this.output1 =
      new CSFakeCertificateOutput();
    this.output2 =
      new CSFakeCertificateOutput();

    this.strings =
      new CSStrings(Locale.getDefault());

    this.acmeProvider =
      new CSFakeAcmeProvider();
    this.acmeServer =
      CSFakeAcmeServer.create(20000);
  }

  @AfterEach
  public void tearDown()
    throws Exception
  {
    CSTestDirectories.deleteDirectory(this.directory);
    this.acmeServer.close();
  }

  /**
   * If the server returns all the right responses, the execution succeeds.
   *
   * @throws Exception On errors
   */

  @Test
  public void testBasicCertificate()
    throws Exception
  {
    final var domain =
      new CSDomain(
        new CSAccount(
          this.accountKeyPair,
          URI.create("acme://localhost:20000/directory/0")
        ),
        "example.com",
        Map.ofEntries(
          Map.entry(
            "example.com",
            new CSCertificate(
              new CSCertificateName("www"),
              this.domainKeyPair,
              List.of("example.com")
            )
          )
        ),
        this.dnsConfigurator,
        Map.ofEntries(
          Map.entry("output0", this.output0),
          Map.entry("output1", this.output1),
          Map.entry("output2", this.output2)
        )
      );

    this.clock.times.add(
      OffsetDateTime.parse("2000-01-01T00:00:00+00:00").toInstant()
    );

    final var executor =
      new CSDomainExecutor(
        new CSStrings(Locale.ROOT),
        CSTelemetryNoOp.noop(),
        Mockito.mock(CSEventServiceType.class),
        new CSOptions(
          this.file,
          Duration.ofSeconds(1L),
          Duration.ofDays(1L),
          Optional.empty(),
          CSFaultInjectionConfiguration.disabled()
        ),
        domain,
        this.clock,
        this.certificates,
        acmeInfo -> {
          return new Session(acmeInfo.acmeURI(), this.acmeProvider);
        }
      );

    executor.execute();

    {
      final var r = this.output0.requests();
      assertEquals(1, r.size());
      assertEquals("example.com", r.peek());
    }

    {
      final var r = this.output1.requests();
      assertEquals(1, r.size());
      assertEquals("example.com", r.peek());
    }

    {
      final var r = this.output2.requests();
      assertEquals(1, r.size());
      assertEquals("example.com", r.peek());
    }

    {
      final var r = this.dnsConfigurator.requests();
      assertEquals(0, r.size());
    }
  }
}
