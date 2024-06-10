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

import com.io7m.certusine.api.CSConfigurationException;
import com.io7m.certusine.api.CSConfigurationParameters;
import com.io7m.certusine.api.CSDNSRecordNameType.CSDNSRecordNameRelative;
import com.io7m.certusine.vultr.CSVultrDNSConfigurators;
import com.io7m.jlexing.core.LexicalPositions;
import com.io7m.quixote.core.QWebServerType;
import com.io7m.quixote.core.QWebServers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Map;

import static com.io7m.certusine.api.CSTelemetryNoOp.noop;
import static java.util.Map.entry;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public final class CSVultrDNSTests
{
  private CSFakeVultrServer fakeServer;
  private CSVultrDNSConfigurators provider;
  private Path directory;
  private QWebServers servers;
  private QWebServerType server;

  @BeforeEach
  public void setup()
    throws Exception
  {
    this.directory =
      CSTestDirectories.createTempDirectory();
    this.fakeServer =
      CSFakeVultrServer.create(20000);
    this.provider =
      new CSVultrDNSConfigurators();
    this.servers =
      new QWebServers();
    this.server =
      this.servers.create(20001);
  }

  @AfterEach
  public void tearDown()
    throws Exception
  {
    CSTestDirectories.deleteDirectory(this.directory);

    this.fakeServer.close();
    this.server.close();
  }

  /**
   * If the server returns all the right responses, the execution succeeds.
   *
   * @throws Exception On errors
   */

  @Test
  public void testVultrOK()
    throws Exception
  {
    final var v =
      this.provider.create(
        new CSConfigurationParameters(
          this.directory,
          LexicalPositions.zero(),
          Map.ofEntries(
            entry("api-key", "abcd"),
            entry("api-base", "http://localhost:20000/"),
            entry("domain", "example.com")
          )
        )
      );

    this.fakeServer.setResponseCode(201);
    v.createTXTRecord(noop(), new CSDNSRecordNameRelative("a"), "b");
  }

  /**
   * If the server returns a failure response, the execution fails.
   *
   * @throws Exception On errors
   */

  @Test
  public void testVultrFailure()
    throws Exception
  {
    final var v =
      this.provider.create(
        new CSConfigurationParameters(
          this.directory,
          LexicalPositions.zero(),
          Map.ofEntries(
            entry("api-key", "abcd"),
            entry("api-base", "http://localhost:20000/"),
            entry("domain", "example.com")
          )
        )
      );

    for (int code = 200; code < 600; ++code) {
      if (code == 201) {
        continue;
      }

      this.fakeServer.setResponseCode(code);
      assertThrows(IOException.class, () -> {
        v.createTXTRecord(noop(), new CSDNSRecordNameRelative("a"), "b");
      });
    }
  }

  /**
   * Missing parameters fail.
   *
   * @throws Exception On errors
   */

  @Test
  public void testVultrMissingRequired0()
    throws Exception
  {
    assertThrows(CSConfigurationException.class, () -> {
      this.provider.create(
        new CSConfigurationParameters(
          this.directory,
          LexicalPositions.zero(),
          Map.ofEntries(
            entry("api-key", "abcd"),
            entry("api-base", "http://localhost:20000/")
          )
        )
      );
    });
  }

  /**
   * Missing parameters fail.
   *
   * @throws Exception On errors
   */

  @Test
  public void testVultrMissingRequired1()
    throws Exception
  {
    assertThrows(CSConfigurationException.class, () -> {
      this.provider.create(
        new CSConfigurationParameters(
          this.directory,
          LexicalPositions.zero(),
          Map.ofEntries(
            entry("api-base", "http://localhost:20000/"),
            entry("domain", "example.com")
          )
        )
      );
    });
  }

  /**
   * If the server returns all the right responses, the execution succeeds.
   *
   * @throws Exception On errors
   */

  @Test
  public void testVultrCreateDelete()
    throws Exception
  {
    final var v =
      this.provider.create(
        new CSConfigurationParameters(
          this.directory,
          LexicalPositions.zero(),
          Map.ofEntries(
            entry("api-key", "abcd"),
            entry("api-base", "http://localhost:20001/"),
            entry("domain", "example.com")
          )
        )
      );

    this.server.addResponse()
      .forPath("/domains/.*")
      .withFixedText(text("vultr-dns-records-0.json"));

    this.server.addResponse()
      .forPath("/domains/.*")
      .withFixedText(text("vultr-dns-records-1.json"));

    this.server.addResponse()
      .forPath("/domains/.*")
      .forMethod("DELETE")
      .withStatus(204)
      .withFixedText("");

    this.server.addResponse()
      .forPath("/domains/.*")
      .forMethod("DELETE")
      .withStatus(204)
      .withFixedText("");

    v.deleteTXTRecord(
      noop(),
      new CSDNSRecordNameRelative("z"), "200.200.200.201"
    );

    {
      final var r =
        this.server.requestsReceived().get(0);
      assertEquals("/domains/example.com/records", r.path());
    }

    {
      final var r =
        this.server.requestsReceived().get(1);
      assertEquals("/domains/example.com/records", r.path());
    }

    {
      final var r =
        this.server.requestsReceived().get(2);
      assertEquals("/domains/example.com/records/ff690447-7b0d-408b-a408-fd2410281a60", r.path());
    }

    {
      final var r =
        this.server.requestsReceived().get(3);
      assertEquals("/domains/example.com/records/68440bec-b17f-4532-a58b-d2b6a7e3b69c", r.path());
    }
  }

  /**
   * If the server returns errors, the execution fails.
   *
   * @throws Exception On errors
   */

  @Test
  public void testVultrCreateDeleteFails0()
    throws Exception
  {
    final var v =
      this.provider.create(
        new CSConfigurationParameters(
          this.directory,
          LexicalPositions.zero(),
          Map.ofEntries(
            entry("api-key", "abcd"),
            entry("api-base", "http://localhost:20001/"),
            entry("domain", "example.com")
          )
        )
      );

    this.server.addResponse()
      .forPath("/domains/.*")
      .withFixedText(text("vultr-dns-records-0.json"));

    this.server.addResponse()
      .forPath("/domains/.*")
      .withFixedText(text("vultr-dns-records-1.json"));

    this.server.addResponse()
      .forPath("/domains/.*")
      .forMethod("DELETE")
      .withStatus(500)
      .withFixedText("");

    assertThrows(IOException.class, () -> {
      v.deleteTXTRecord(
        noop(),
        new CSDNSRecordNameRelative("z"), "200.200.200.201"
      );
    });

    {
      final var r =
        this.server.requestsReceived().get(0);
      assertEquals("/domains/example.com/records", r.path());
    }

    {
      final var r =
        this.server.requestsReceived().get(1);
      assertEquals("/domains/example.com/records", r.path());
    }

    {
      final var r =
        this.server.requestsReceived().get(2);
      assertEquals("/domains/example.com/records/ff690447-7b0d-408b-a408-fd2410281a60", r.path());
    }
  }

  /**
   * If the server returns errors, the execution fails.
   *
   * @throws Exception On errors
   */

  @Test
  public void testVultrCreateDeleteFails1()
    throws Exception
  {
    final var v =
      this.provider.create(
        new CSConfigurationParameters(
          this.directory,
          LexicalPositions.zero(),
          Map.ofEntries(
            entry("api-key", "abcd"),
            entry("api-base", "http://localhost:20001/"),
            entry("domain", "example.com")
          )
        )
      );

    this.server.addResponse()
      .forPath("/domains/.*")
      .withFixedText(text("vultr-dns-records-0.json"));

    this.server.addResponse()
      .forPath("/domains/.*")
      .withStatus(500)
      .withFixedText(text("vultr-dns-records-1.json"));

    assertThrows(IOException.class, () -> {
      v.deleteTXTRecord(
        noop(),
        new CSDNSRecordNameRelative("z"), "200.200.200.201"
      );
    });

    {
      final var r =
        this.server.requestsReceived().get(0);
      assertEquals("/domains/example.com/records", r.path());
    }

    {
      final var r =
        this.server.requestsReceived().get(1);
      assertEquals("/domains/example.com/records", r.path());
    }
  }

  private static String text(
    final String name)
    throws IOException
  {
    try (var stream =
           CSVultrDNSTests.class.getResourceAsStream(
             "/com/io7m/certusine/tests/%s".formatted(name)
           )) {
      return new String(
        stream.readAllBytes(),
        StandardCharsets.UTF_8
      );
    }
  }
}
