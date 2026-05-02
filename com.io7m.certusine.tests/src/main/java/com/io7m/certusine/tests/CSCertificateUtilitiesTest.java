/*
 * Copyright © 2025 Mark Raynsford <code@io7m.com> https://www.io7m.com
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


import com.io7m.certusine.api.CSCertificateName;
import com.io7m.certusine.api.CSTelemetryNoOp;
import com.io7m.certusine.certstore.api.CSCertificateStored;
import com.io7m.certusine.vanilla.CSCertificateUtilities;
import com.io7m.certusine.vanilla.CSServices;
import com.io7m.certusine.vanilla.internal.store.CSCertificateStoreServiceType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;

public final class CSCertificateUtilitiesTest
{
  private Path directory;
  private Path configFile;

  @BeforeEach
  public void setup(
    final @TempDir Path directory)
    throws IOException
  {
    this.directory =
      directory;
    this.configFile =
      this.directory.resolve("config.xml");

    CSTestDirectories.resourceOf(
      CSConfigurationParserTest.class,
      this.directory,
      "fake.pub"
    );
    CSTestDirectories.resourceOf(
      CSConfigurationParserTest.class,
      this.directory,
      "fake.pri"
    );
  }

  @Test
  public void testRemovalDisabled()
    throws Exception
  {
    final var file =
      CSTestDirectories.resourceOf(
        CSConfigurationParserTest.class,
        this.directory,
        "configuration-basic.xml"
      );

    Files.copy(file, this.configFile);

    final var services =
      CSServices.create(
        Locale.getDefault(),
        this.configFile,
        Clock.systemUTC(),
        CSTelemetryNoOp.noop()
      );

    final var store =
      services.requireService(CSCertificateStoreServiceType.class)
        .store();

    store.put(new CSCertificateStored(
      "example.com",
      new CSCertificateName("www"),
      OffsetDateTime.now(),
      OffsetDateTime.now().plus(Duration.ofDays(30L)),
      "CERT!",
      "CERT!"
    ));
    store.put(new CSCertificateStored(
      "example.com",
      new CSCertificateName("mail"),
      OffsetDateTime.now(),
      OffsetDateTime.now().plus(Duration.ofDays(30L)),
      "CERT!",
      "CERT!"
    ));
    store.put(new CSCertificateStored(
      "example.com",
      new CSCertificateName("wildcard"),
      OffsetDateTime.now(),
      OffsetDateTime.now().plus(Duration.ofDays(30L)),
      "CERT!",
      "CERT!"
    ));

    CSCertificateUtilities.cleanUpUnusedCertificates(services);

    assertEquals(3, store.all().size());
  }

  @Test
  public void testRemovalEnabledNoneRemoved()
    throws Exception
  {
    final var file =
      CSTestDirectories.resourceOf(
        CSConfigurationParserTest.class,
        this.directory,
        "configuration-basic-with-removal.xml"
      );

    Files.copy(file, this.configFile);

    final var services =
      CSServices.create(
        Locale.getDefault(),
        this.configFile,
        Clock.systemUTC(),
        CSTelemetryNoOp.noop()
      );

    final var store =
      services.requireService(CSCertificateStoreServiceType.class)
        .store();

    store.put(new CSCertificateStored(
      "example.com",
      new CSCertificateName("www"),
      OffsetDateTime.now(),
      OffsetDateTime.now().plus(Duration.ofDays(30L)),
      "CERT!",
      "CERT!"
    ));
    store.put(new CSCertificateStored(
      "example.com",
      new CSCertificateName("mail"),
      OffsetDateTime.now(),
      OffsetDateTime.now().plus(Duration.ofDays(30L)),
      "CERT!",
      "CERT!"
    ));
    store.put(new CSCertificateStored(
      "example.com",
      new CSCertificateName("wildcard"),
      OffsetDateTime.now(),
      OffsetDateTime.now().plus(Duration.ofDays(30L)),
      "CERT!",
      "CERT!"
    ));

    CSCertificateUtilities.cleanUpUnusedCertificates(services);

    assertEquals(3, store.all().size());
  }

  @Test
  public void testRemovalEnabledNonePresent()
    throws Exception
  {
    final var file =
      CSTestDirectories.resourceOf(
        CSConfigurationParserTest.class,
        this.directory,
        "configuration-basic-with-removal.xml"
      );

    Files.copy(file, this.configFile);

    final var services =
      CSServices.create(
        Locale.getDefault(),
        this.configFile,
        Clock.systemUTC(),
        CSTelemetryNoOp.noop()
      );

    CSCertificateUtilities.cleanUpUnusedCertificates(services);
  }

  @Test
  public void testRemovalEnabledAllRemoved()
    throws Exception
  {
    final var file =
      CSTestDirectories.resourceOf(
        CSConfigurationParserTest.class,
        this.directory,
        "configuration-basic-with-removal-nocerts.xml"
      );

    Files.copy(file, this.configFile);

    final var services =
      CSServices.create(
        Locale.getDefault(),
        this.configFile,
        Clock.systemUTC(),
        CSTelemetryNoOp.noop()
      );

    final var store =
      services.requireService(CSCertificateStoreServiceType.class)
        .store();

    store.put(new CSCertificateStored(
      "example.com",
      new CSCertificateName("www"),
      OffsetDateTime.now(),
      OffsetDateTime.now().plus(Duration.ofDays(30L)),
      "CERT!",
      "CERT!"
    ));
    store.put(new CSCertificateStored(
      "example.com",
      new CSCertificateName("mail"),
      OffsetDateTime.now(),
      OffsetDateTime.now().plus(Duration.ofDays(30L)),
      "CERT!",
      "CERT!"
    ));
    store.put(new CSCertificateStored(
      "example.com",
      new CSCertificateName("wildcard"),
      OffsetDateTime.now(),
      OffsetDateTime.now().plus(Duration.ofDays(30L)),
      "CERT!",
      "CERT!"
    ));

    CSCertificateUtilities.cleanUpUnusedCertificates(services);

    assertEquals(0, store.all().size());
  }
}
