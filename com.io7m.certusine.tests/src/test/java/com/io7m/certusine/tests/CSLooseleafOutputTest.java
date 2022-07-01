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
import com.io7m.certusine.api.CSCertificateOutputData;
import com.io7m.certusine.api.CSConfigurationException;
import com.io7m.certusine.api.CSConfigurationParameters;
import com.io7m.certusine.looseleaf.CSLLOutputProvider;
import com.io7m.jlexing.core.LexicalPositions;
import com.io7m.looseleaf.security.LLPassword;
import com.io7m.looseleaf.security.LLPasswordAlgorithmPBKDF2HmacSHA256;
import com.io7m.looseleaf.server.LLServers;
import com.io7m.looseleaf.server.api.LLServerAddress;
import com.io7m.looseleaf.server.api.LLServerConfiguration;
import com.io7m.looseleaf.server.api.LLServerGrant;
import com.io7m.looseleaf.server.api.LLServerHashedPassword;
import com.io7m.looseleaf.server.api.LLServerRole;
import com.io7m.looseleaf.server.api.LLServerType;
import com.io7m.looseleaf.server.api.LLServerUser;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static com.io7m.looseleaf.server.api.LLServerAction.READ;
import static com.io7m.looseleaf.server.api.LLServerAction.WRITE;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Map.entry;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public final class CSLooseleafOutputTest
{
  private static final Logger LOG =
    LoggerFactory.getLogger(CSLooseleafOutputTest.class);

  private Path directory;
  private CSLLOutputProvider outputs;
  private LLServers servers;
  private LLPassword password;
  private LLServerType server;

  @BeforeEach
  public void setup()
    throws Exception
  {
    this.directory =
      CSTestDirectories.createTempDirectory();
    this.outputs =
      new CSLLOutputProvider();

    this.servers =
      new LLServers();

    this.password =
      LLPasswordAlgorithmPBKDF2HmacSHA256.create()
        .createHashed("password");

    this.server =
      this.servers.open(
        new LLServerConfiguration(
          null,
          List.of(
            new LLServerAddress("localhost", 20000)
          ),
          this.directory.resolve("looseleaf.db"),
          List.of(
            new LLServerRole(
              "main",
              List.of(
                new LLServerGrant(READ, "/certificates/*"),
                new LLServerGrant(WRITE, "/certificates/*")
              ))
          ),
          List.of(new LLServerUser(
            "grouch",
            new LLServerHashedPassword(
              this.password.algorithm().identifier(),
              this.password.salt(),
              this.password.hash()
            ),
            List.of("main")
          ))
        )
      );
  }

  @AfterEach
  public void tearDown()
    throws Exception
  {
    this.server.close();
    CSTestDirectories.deleteDirectory(this.directory);
  }

  @Test
  public void testMisconfigured()
    throws Exception
  {
    final var ex =
      assertThrows(CSConfigurationException.class, () -> {
        this.outputs.create(
          "example",
          new CSConfigurationParameters(
            this.directory,
            LexicalPositions.zero(),
            Map.ofEntries()
          )
        );
      });

    LOG.debug("exception: ", ex);
    assertTrue(
      ex.errors()
        .stream()
        .anyMatch(e -> Objects.equals(
          e.errorCode(),
          "error-parameter-required"))
    );
  }

  @Test
  public void testWriteOutput()
    throws Exception
  {
    final var output =
      this.outputs.create(
        "example",
        new CSConfigurationParameters(
          this.directory,
          LexicalPositions.zero(),
          Map.ofEntries(
            entry("endpoint", "http://localhost:20000/"),
            entry("username", "grouch"),
            entry("password", "password")

          )
        )
      );

    output.write(new CSCertificateOutputData(
      "example.com",
      new CSCertificateName("www"),
      "PUB",
      "PRI",
      "CERT",
      "CERTFULL"
    ));

    assertEquals("PUB", get("/certificates/example.com/www/public_key"));
    assertEquals("PRI", get("/certificates/example.com/www/private_key"));
    assertEquals("CERT", get("/certificates/example.com/www/certificate"));
    assertEquals(
      "CERTFULL",
      get("/certificates/example.com/www/certificate_full_chain"));
  }

  @Test
  public void testWriteOutputAuthenticationFailure()
    throws Exception
  {
    final var output =
      this.outputs.create(
        "example",
        new CSConfigurationParameters(
          this.directory,
          LexicalPositions.zero(),
          Map.ofEntries(
            entry("endpoint", "http://localhost:20000/"),
            entry("username", "bigbird"),
            entry("password", "password")

          )
        )
      );

    final var ex = assertThrows(IOException.class, () -> {
      output.write(new CSCertificateOutputData(
        "example.com",
        new CSCertificateName("www"),
        "PUB",
        "PRI",
        "CERT",
        "CERTFULL"
      ));
    });
    assertEquals("Server returned an error status: 401", ex.getMessage());
  }

  private static String get(
    final String path)
    throws Exception
  {
    final var client =
      HttpClient.newHttpClient();

    final var authorization =
      "Basic " + base64("%s:%s".formatted("grouch", "password"));

    final var request =
      HttpRequest.newBuilder()
        .header("Authorization", authorization)
        .uri(URI.create("http://localhost:20000/v1/read" + path))
        .build();

    final var httpResponse =
      client.send(request, HttpResponse.BodyHandlers.ofString());

    return httpResponse.body();
  }

  private static String base64(
    final String formatted)
  {
    return Base64.getUrlEncoder().encodeToString(formatted.getBytes(UTF_8));
  }
}
