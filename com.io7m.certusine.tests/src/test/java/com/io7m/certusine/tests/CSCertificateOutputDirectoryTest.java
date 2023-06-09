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
import com.io7m.certusine.vanilla.internal.CSCertificateOutputDirectory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

import static com.io7m.certusine.api.CSTelemetryNoOp.noop;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public final class CSCertificateOutputDirectoryTest
{
  private KeyPair keyPair;
  private Path directory;

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
    this.keyPair =
      generateKeyPair();
  }

  @AfterEach
  public void tearDown()
    throws Exception
  {
    CSTestDirectories.deleteDirectory(this.directory);
  }

  @Test
  public void testBasicCertificate()
    throws Exception
  {
    final var output =
      new CSCertificateOutputDirectory("out", this.directory);

    output.write(
      noop(),
      new CSCertificateOutputData(
        "example.com",
        new CSCertificateName("www"),
        "PUB",
        "PRI",
        "CERT",
        "CERT_CHAIN"
      )
    );

    final var domainDir =
      this.directory.resolve("example.com");
    final var certDir =
      domainDir.resolve("www");
    final var pubKeyFile =
      certDir.resolve("public.key");
    final var priKeyFile =
      certDir.resolve("private.key");
    final var certFile =
      certDir.resolve("certificate.pem");
    final var certFullFile =
      certDir.resolve("full_chain.pem");

    assertTrue(Files.isDirectory(domainDir));
    assertTrue(Files.isDirectory(certDir));

    try (var reader = Files.newBufferedReader(pubKeyFile)) {
      assertEquals("PUB", reader.readLine());
    }

    try (var reader = Files.newBufferedReader(priKeyFile)) {
      assertEquals("PRI", reader.readLine());
    }

    try (var reader = Files.newBufferedReader(certFile)) {
      assertEquals("CERT", reader.readLine());
    }

    try (var reader = Files.newBufferedReader(certFullFile)) {
      assertEquals("CERT_CHAIN", reader.readLine());
    }
  }
}
