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

import com.io7m.certusine.api.CSCertificateName;
import com.io7m.certusine.api.CSTelemetryServiceType;
import com.io7m.certusine.certstore.api.CSCertificateStored;
import com.io7m.certusine.vanilla.internal.store.CSCertificateStoreH2MVFactory;
import com.io7m.repetoir.core.RPServiceDirectory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.file.Path;
import java.time.OffsetDateTime;
import java.util.Optional;

import static java.time.ZoneOffset.UTC;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public final class CSCertificateStoreH2MVTest
{
  private Path directory;
  private Path file;
  private CSCertificateStoreH2MVFactory stores;

  @BeforeEach
  public void setup()
    throws IOException
  {
    this.directory =
      CSTestDirectories.createTempDirectory();
    this.file =
      this.directory.resolve("store.db");
    this.stores =
      new CSCertificateStoreH2MVFactory();
  }

  @AfterEach
  public void tearDown()
    throws IOException
  {
    CSTestDirectories.deleteDirectory(this.directory);
  }

  @Test
  public void testCRUD()
    throws Exception
  {
    final var www =
      new CSCertificateName("www");

    final var certificate0 =
      new CSCertificateStored(
        "example.com",
        www,
        OffsetDateTime.of(2000, 1, 1, 0, 0, 0, 0, UTC),
        OffsetDateTime.of(2001, 1, 1, 0, 0, 0, 0, UTC),
        "-- BEGIN CERTIFICATE --",
        "-- BEGIN CERTIFICATE --"
      );

    final var certificate1 =
      new CSCertificateStored(
        "example.com",
        www,
        OffsetDateTime.of(2002, 1, 1, 0, 0, 0, 0, UTC),
        OffsetDateTime.of(2003, 1, 1, 0, 0, 0, 0, UTC),
        "-- BEGIN CERTIFICATE --",
        "-- BEGIN CERTIFICATE --"
      );

    try (var store = this.stores.open(this.file)) {
      assertEquals(
        Optional.empty(),
        store.find("example.com", www)
      );
    }

    try (var store = this.stores.open(this.file)) {
      store.put(certificate0);
      assertEquals(
        Optional.of(certificate0),
        store.find("example.com", www)
      );
    }

    try (var store = this.stores.open(this.file)) {
      assertEquals(
        Optional.of(certificate0),
        store.find("example.com", www)
      );
    }

    try (var store = this.stores.open(this.file)) {
      store.put(certificate1);
      assertEquals(
        Optional.of(certificate1),
        store.find("example.com", www)
      );
    }

    try (var store = this.stores.open(this.file)) {
      assertEquals(
        Optional.of(certificate1),
        store.find("example.com", www)
      );
    }

    try (var store = this.stores.open(this.file)) {
      assertTrue(store.delete("example.com", www));
      assertFalse(store.delete("example.com", www));
      assertEquals(
        Optional.empty(),
        store.find("example.com", www)
      );
    }

    try (var store = this.stores.open(this.file)) {
      assertEquals(
        Optional.empty(),
        store.find("example.com", www)
      );
    }
  }
}
