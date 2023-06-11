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
import com.io7m.certusine.api.CSConfigurationParameters;
import com.io7m.certusine.looseleaf.CSLLCredentials;
import com.io7m.certusine.looseleaf.CSLLDownloader;
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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.io7m.certusine.api.CSTelemetryNoOp.noop;
import static com.io7m.looseleaf.server.api.LLServerAction.READ;
import static com.io7m.looseleaf.server.api.LLServerAction.WRITE;
import static java.util.Map.entry;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public final class CSLooseleafDownloaderTest
{
  private static final Logger LOG =
    LoggerFactory.getLogger(CSLooseleafDownloaderTest.class);

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
          )),
          Optional.empty(),
          Optional.empty()
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

    output.write(
      noop(),
      new CSCertificateOutputData(
      "example.com",
      new CSCertificateName("www"),
      "PUB",
      "PRI",
      "CERT",
      "CERTFULL"
    ));

    final var data =
      this.directory.resolve("output");

    final var downloader =
      CSLLDownloader.create(
        data,
        "http://localhost:20000/",
        new CSLLCredentials("grouch", "password"),
        "example.com",
        new CSCertificateName("www")
      );

    downloader.execute();

    assertEquals(
      "PUB", this.read("example.com", "www", "public_key"));
    assertEquals(
      "PRI", this.read("example.com", "www", "private_key"));
    assertEquals(
      "CERT", this.read("example.com", "www", "certificate"));
    assertEquals(
      "CERTFULL", this.read("example.com", "www", "certificate_full_chain"));
  }

  @Test
  public void testAuthenticationFails()
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

    output.write(
      noop(),
      new CSCertificateOutputData(
      "example.com",
      new CSCertificateName("www"),
      "PUB",
      "PRI",
      "CERT",
      "CERTFULL"
    ));

    final var data =
      this.directory.resolve("output");

    final var downloader =
      CSLLDownloader.create(
        data,
        "http://localhost:20000/",
        new CSLLCredentials("grouchy", "passwordy"),
        "example.com",
        new CSCertificateName("www")
      );

    final var ex =
      assertThrows(IOException.class, downloader::execute);
    LOG.error("exception: ", ex);
  }

  @Test
  public void testKeysMissing()
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

    final var data =
      this.directory.resolve("output");

    final var downloader =
      CSLLDownloader.create(
        data,
        "http://localhost:20000/",
        new CSLLCredentials("grouch", "password"),
        "example.com",
        new CSCertificateName("www")
      );

    final var ex =
      assertThrows(IOException.class, downloader::execute);
    LOG.error("exception: ", ex);
  }

  private String read(
    final String domain,
    final String cert,
    final String file)
    throws IOException
  {
    final var data =
      this.directory.resolve("output")
        .resolve("certificates")
        .resolve(domain)
        .resolve(cert)
        .resolve(file);

    return Files.readString(data);
  }
}
