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
import com.io7m.certusine.gandi.CSGandiDNSConfigurators;
import com.io7m.jlexing.core.LexicalPositions;
import com.io7m.quixote.core.QWebServerType;
import com.io7m.quixote.core.QWebServers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Map;

import static com.io7m.certusine.api.CSTelemetryNoOp.noop;
import static java.util.Map.entry;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public final class CSGandiDNSTests
{
  private CSGandiDNSConfigurators provider;
  private Path directory;
  private QWebServerType webServer;

  @BeforeEach
  public void setup()
    throws Exception
  {
    this.directory =
      CSTestDirectories.createTempDirectory();
    this.provider =
      new CSGandiDNSConfigurators();
    this.webServer =
      QWebServers.createServer(20000);
  }

  @AfterEach
  public void tearDown()
    throws Exception
  {
    CSTestDirectories.deleteDirectory(this.directory);

    this.webServer.close();
  }

  /**
   * If the server returns all the right responses, the execution succeeds.
   *
   * @throws Exception On errors
   */

  @Test
  public void testGandiCreateNonexistent0()
    throws Exception
  {
    final var v =
      this.provider.create(
        new CSConfigurationParameters(
          this.directory,
          LexicalPositions.zero(),
          Map.ofEntries(
            entry("personal-access-token", "abcd"),
            entry("api-base", "http://localhost:20000/"),
            entry("domain", "example.com")
          )
        )
      );

    this.webServer.addResponse()
      .forMethod("GET")
      .forPath("/v5/livedns/domains/example.com/records/a")
      .withStatus(404)
      .withContentLength(0L);

    this.webServer.addResponse()
      .forMethod("PUT")
      .forPath("/v5/livedns/domains/example.com/records/a")
      .withStatus(200)
      .withContentLength(0L);

    v.createTXTRecord(noop(), new CSDNSRecordNameRelative("a"), "b");

    final var received = new ArrayList<>(this.webServer.requestsReceived());
    {
      final var req = received.remove(0);
      assertEquals("GET", req.method());
      assertEquals("Bearer abcd", req.headers().get("authorization"));
      assertEquals("/v5/livedns/domains/example.com/records/a", req.path());
    }
    {
      final var req = received.remove(0);
      assertEquals("PUT", req.method());
      assertEquals("Bearer abcd", req.headers().get("authorization"));
      assertEquals("/v5/livedns/domains/example.com/records/a", req.path());
    }
    assertEquals(0, received.size());
  }

  /**
   * If the server returns all the right responses, the execution succeeds.
   *
   * @throws Exception On errors
   */

  @Test
  public void testGandiCreateNonexistent1()
    throws Exception
  {
    final var v =
      this.provider.create(
        new CSConfigurationParameters(
          this.directory,
          LexicalPositions.zero(),
          Map.ofEntries(
            entry("personal-access-token", "abcd"),
            entry("api-base", "http://localhost:20000/"),
            entry("domain", "example.com")
          )
        )
      );

    this.webServer.addResponse()
      .forMethod("GET")
      .forPath("/v5/livedns/domains/example.com/records/a")
      .withStatus(200)
      .withFixedText("[]");

    this.webServer.addResponse()
      .forMethod("PUT")
      .forPath("/v5/livedns/domains/example.com/records/a")
      .withStatus(200)
      .withContentLength(0L);

    v.createTXTRecord(noop(), new CSDNSRecordNameRelative("a"), "b");

    final var received = new ArrayList<>(this.webServer.requestsReceived());
    {
      final var req = received.remove(0);
      assertEquals("GET", req.method());
      assertEquals("Bearer abcd", req.headers().get("authorization"));
      assertEquals("/v5/livedns/domains/example.com/records/a", req.path());
    }
    {
      final var req = received.remove(0);
      assertEquals("PUT", req.method());
      assertEquals("Bearer abcd", req.headers().get("authorization"));
      assertEquals("/v5/livedns/domains/example.com/records/a", req.path());
    }
    assertEquals(0, received.size());
  }

  /**
   * If the server returns all the right responses, the execution succeeds.
   *
   * @throws Exception On errors
   */

  @Test
  public void testGandiCreateExisting0()
    throws Exception
  {
    final var v =
      this.provider.create(
        new CSConfigurationParameters(
          this.directory,
          LexicalPositions.zero(),
          Map.ofEntries(
            entry("personal-access-token", "abcd"),
            entry("api-base", "http://localhost:20000/"),
            entry("domain", "example.com")
          )
        )
      );

    this.webServer.addResponse()
      .forMethod("GET")
      .forPath("/v5/livedns/domains/example.com/records/a")
      .withStatus(200)
      .withFixedText("""
                       [
                          {
                            "rrset_type": "TXT",
                            "rrset_values": []
                          }
                       ]
                       """);

    this.webServer.addResponse()
      .forMethod("PUT")
      .forPath("/v5/livedns/domains/example.com/records/a")
      .withStatus(200)
      .withContentLength(0L);

    v.createTXTRecord(noop(), new CSDNSRecordNameRelative("a"), "b");

    final var received = new ArrayList<>(this.webServer.requestsReceived());
    {
      final var req = received.remove(0);
      assertEquals("GET", req.method());
      assertEquals("Bearer abcd", req.headers().get("authorization"));
      assertEquals("/v5/livedns/domains/example.com/records/a", req.path());
    }
    {
      final var req = received.remove(0);
      assertEquals("PUT", req.method());
      assertEquals("Bearer abcd", req.headers().get("authorization"));
      assertEquals("/v5/livedns/domains/example.com/records/a", req.path());
    }
    assertEquals(0, received.size());
  }

  /**
   * If the server returns all the right responses, the execution succeeds.
   *
   * @throws Exception On errors
   */

  @Test
  public void testGandiCreateExisting1()
    throws Exception
  {
    final var v =
      this.provider.create(
        new CSConfigurationParameters(
          this.directory,
          LexicalPositions.zero(),
          Map.ofEntries(
            entry("personal-access-token", "abcd"),
            entry("api-base", "http://localhost:20000/"),
            entry("domain", "example.com")
          )
        )
      );

    this.webServer.addResponse()
      .forMethod("GET")
      .forPath("/v5/livedns/domains/example.com/records/a")
      .withStatus(200)
      .withFixedText("""
                       [
                          {
                            "rrset_type": "TXT",
                            "rrset_values": ["b"]
                          }
                       ]
                       """);

    this.webServer.addResponse()
      .forMethod("PUT")
      .forPath("/v5/livedns/domains/example.com/records/a")
      .withStatus(200)
      .withContentLength(0L);

    v.createTXTRecord(noop(), new CSDNSRecordNameRelative("a"), "b");

    final var received = new ArrayList<>(this.webServer.requestsReceived());
    {
      final var req = received.remove(0);
      assertEquals("GET", req.method());
      assertEquals("Bearer abcd", req.headers().get("authorization"));
      assertEquals("/v5/livedns/domains/example.com/records/a", req.path());
    }
    assertEquals(0, received.size());
  }

  /**
   * If the server returns a failure response, the execution fails.
   *
   * @throws Exception On errors
   */

  @Test
  public void testGandiFailure()
    throws Exception
  {
    final var v =
      this.provider.create(
        new CSConfigurationParameters(
          this.directory,
          LexicalPositions.zero(),
          Map.ofEntries(
            entry("personal-access-token", "abcd"),
            entry("api-base", "http://localhost:20000/"),
            entry("domain", "example.com")
          )
        )
      );

    for (int code = 200; code < 600; ++code) {
      if (code == 200 || code == 201) {
        continue;
      }

      this.webServer.addResponse()
        .forMethod("GET")
        .forPath("/v5/livedns/domains/example.com/records/a")
        .withStatus(200)
        .withFixedText("");

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
  public void testGandiMissingRequired0()
    throws Exception
  {
    assertThrows(CSConfigurationException.class, () -> {
      this.provider.create(
        new CSConfigurationParameters(
          this.directory,
          LexicalPositions.zero(),
          Map.ofEntries(
            entry("personal-access-token", "abcd"),
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
  public void testGandiMissingRequired1()
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
  public void testGandiDeleteNonexistent0()
    throws Exception
  {
    final var v =
      this.provider.create(
        new CSConfigurationParameters(
          this.directory,
          LexicalPositions.zero(),
          Map.ofEntries(
            entry("personal-access-token", "abcd"),
            entry("api-base", "http://localhost:20000/"),
            entry("domain", "example.com")
          )
        )
      );

    this.webServer.addResponse()
      .forMethod("GET")
      .forPath("/v5/livedns/domains/example.com/records/a")
      .withStatus(404)
      .withContentLength(0L);

    this.webServer.addResponse()
      .forMethod("PUT")
      .forPath("/v5/livedns/domains/example.com/records/a")
      .withStatus(200)
      .withContentLength(0L);

    v.deleteTXTRecord(noop(), new CSDNSRecordNameRelative("a"), "b");

    final var received = new ArrayList<>(this.webServer.requestsReceived());
    {
      final var req = received.remove(0);
      assertEquals("GET", req.method());
      assertEquals("Bearer abcd", req.headers().get("authorization"));
      assertEquals("/v5/livedns/domains/example.com/records/a", req.path());
    }
    assertEquals(0, received.size());
  }

  /**
   * If the server returns all the right responses, the execution succeeds.
   *
   * @throws Exception On errors
   */

  @Test
  public void testGandiDeleteNonexistent1()
    throws Exception
  {
    final var v =
      this.provider.create(
        new CSConfigurationParameters(
          this.directory,
          LexicalPositions.zero(),
          Map.ofEntries(
            entry("personal-access-token", "abcd"),
            entry("api-base", "http://localhost:20000/"),
            entry("domain", "example.com")
          )
        )
      );

    this.webServer.addResponse()
      .forMethod("GET")
      .forPath("/v5/livedns/domains/example.com/records/a")
      .withStatus(200)
      .withFixedText("[]");

    this.webServer.addResponse()
      .forMethod("PUT")
      .forPath("/v5/livedns/domains/example.com/records/a")
      .withStatus(200)
      .withContentLength(0L);

    v.deleteTXTRecord(noop(), new CSDNSRecordNameRelative("a"), "b");

    final var received = new ArrayList<>(this.webServer.requestsReceived());
    {
      final var req = received.remove(0);
      assertEquals("GET", req.method());
      assertEquals("Bearer abcd", req.headers().get("authorization"));
      assertEquals("/v5/livedns/domains/example.com/records/a", req.path());
    }
    assertEquals(0, received.size());
  }

  /**
   * If the server returns all the right responses, the execution succeeds.
   *
   * @throws Exception On errors
   */

  @Test
  public void testGandiDeleteExists0()
    throws Exception
  {
    final var v =
      this.provider.create(
        new CSConfigurationParameters(
          this.directory,
          LexicalPositions.zero(),
          Map.ofEntries(
            entry("personal-access-token", "abcd"),
            entry("api-base", "http://localhost:20000/"),
            entry("domain", "example.com")
          )
        )
      );

    this.webServer.addResponse()
      .forMethod("GET")
      .forPath("/v5/livedns/domains/example.com/records/a")
      .withStatus(200)
      .withFixedText("""
                       [
                          {
                            "rrset_type": "TXT",
                            "rrset_values": ["b"]
                          }
                       ]
                       """);

    this.webServer.addResponse()
      .forMethod("DELETE")
      .forPath("/v5/livedns/domains/example.com/records/a")
      .withStatus(200)
      .withContentLength(0L);

    v.deleteTXTRecord(noop(), new CSDNSRecordNameRelative("a"), "b");

    final var received = new ArrayList<>(this.webServer.requestsReceived());
    {
      final var req = received.remove(0);
      assertEquals("GET", req.method());
      assertEquals("Bearer abcd", req.headers().get("authorization"));
      assertEquals("/v5/livedns/domains/example.com/records/a", req.path());
    }
    {
      final var req = received.remove(0);
      assertEquals("DELETE", req.method());
      assertEquals("Bearer abcd", req.headers().get("authorization"));
      assertEquals("/v5/livedns/domains/example.com/records/a", req.path());
    }
    assertEquals(0, received.size());
  }


  /**
   * If the server returns all the right responses, the execution succeeds.
   *
   * @throws Exception On errors
   */

  @Test
  public void testGandiDeleteExists1()
    throws Exception
  {
    final var v =
      this.provider.create(
        new CSConfigurationParameters(
          this.directory,
          LexicalPositions.zero(),
          Map.ofEntries(
            entry("personal-access-token", "abcd"),
            entry("api-base", "http://localhost:20000/"),
            entry("domain", "example.com")
          )
        )
      );

    this.webServer.addResponse()
      .forMethod("GET")
      .forPath("/v5/livedns/domains/example.com/records/a")
      .withStatus(200)
      .withFixedText("""
                       [
                          {
                            "rrset_type": "TXT",
                            "rrset_values": ["a", "b"]
                          }
                       ]
                       """);

    this.webServer.addResponse()
      .forMethod("PUT")
      .forPath("/v5/livedns/domains/example.com/records/a")
      .withStatus(200)
      .withContentLength(0L);

    v.deleteTXTRecord(noop(), new CSDNSRecordNameRelative("a"), "b");

    final var received = new ArrayList<>(this.webServer.requestsReceived());
    {
      final var req = received.remove(0);
      assertEquals("GET", req.method());
      assertEquals("Bearer abcd", req.headers().get("authorization"));
      assertEquals("/v5/livedns/domains/example.com/records/a", req.path());
    }
    {
      final var req = received.remove(0);
      assertEquals("PUT", req.method());
      assertEquals("Bearer abcd", req.headers().get("authorization"));
      assertEquals("/v5/livedns/domains/example.com/records/a", req.path());
    }
    assertEquals(0, received.size());
  }
}
