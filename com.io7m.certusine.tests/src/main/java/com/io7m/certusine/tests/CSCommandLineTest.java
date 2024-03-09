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

import com.io7m.certusine.cmdline.Main;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Path;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;

public final class CSCommandLineTest
{
  private static final Logger LOG =
    LoggerFactory.getLogger(CSCommandLineTest.class);

  private PrintStream initialStdout;
  private PrintStream initialStderr;
  private ByteArrayOutputStream captureStdoutStream;
  private ByteArrayOutputStream captureStderrStream;
  private PrintStream captureStdout;
  private PrintStream captureStderr;
  private Path directory;

  @BeforeEach
  public void setup()
    throws IOException
  {
    this.directory =
      CSTestDirectories.createTempDirectory();

    LOG.debug("capturing i/o");

    this.initialStdout = System.out;
    this.initialStderr = System.err;

    this.captureStdoutStream =
      new ByteArrayOutputStream();
    this.captureStderrStream =
      new ByteArrayOutputStream();
    this.captureStdout =
      new PrintStream(this.captureStdoutStream, true, UTF_8);
    this.captureStderr =
      new PrintStream(this.captureStderrStream, true, UTF_8);

    System.setOut(this.captureStdout);
    System.setErr(this.captureStderr);
  }

  @AfterEach
  public void tearDown()
    throws IOException
  {
    System.out.flush();
    System.err.flush();

    System.setOut(this.initialStdout);
    System.setErr(this.initialStderr);

    LOG.debug("{}", this.captureStdoutStream.toString(UTF_8));
    LOG.debug("{}", this.captureStderrStream.toString(UTF_8));

    CSTestDirectories.deleteDirectory(this.directory);
  }

  @Test
  public void testNoArguments()
  {
    final var r = Main.mainExitless(new String[]{

    });
    assertEquals(0, r);
  }

  @Test
  public void testHelpHelp()
  {
    final var r = Main.mainExitless(new String[]{
      "help",
      "help"
    });
    assertEquals(0, r);
  }

  @Test
  public void testHelpCheckConfiguration()
  {
    final var r = Main.mainExitless(new String[]{
      "help",
      "check-configuration"
    });
    assertEquals(0, r);
  }

  @Test
  public void testHelpGenerateKeyPair()
  {
    final var r = Main.mainExitless(new String[]{
      "help",
      "generate-keypair"
    });
    assertEquals(0, r);
  }

  @Test
  public void testHelpRenew()
  {
    final var r = Main.mainExitless(new String[]{
      "help",
      "renew"
    });
    assertEquals(0, r);
  }

  @Test
  public void testHelpShowCertificateOutputs()
  {
    final var r = Main.mainExitless(new String[]{
      "help",
      "show-certificate-outputs"
    });
    assertEquals(0, r);
  }

  @Test
  public void testHelpShowDNSConfigurators()
  {
    final var r = Main.mainExitless(new String[]{
      "help",
      "show-dns-configurators"
    });
    assertEquals(0, r);
  }

  @Test
  public void testGenerateKeyPair()
  {
    final var publicKey =
      this.directory.resolve("test.pub")
        .toAbsolutePath();
    final var privateKey =
      this.directory.resolve("test.pri")
        .toAbsolutePath();

    int r = Main.mainExitless(new String[]{
      "generate-keypair",
      "--public-key",
      publicKey.toString(),
      "--private-key",
      privateKey.toString()
    });
    assertEquals(0, r);

    r = Main.mainExitless(new String[]{
      "generate-keypair",
      "--public-key",
      publicKey.toString(),
      "--private-key",
      privateKey.toString()
    });
    assertEquals(1, r);

    r = Main.mainExitless(new String[]{
      "generate-keypair",
      "--public-key",
      publicKey.toString(),
      "--private-key",
      privateKey.toString(),
      "--overwrite",
      "true"
    });
    assertEquals(0, r);
  }

  @Test
  public void testCheckConfigurationNonexistent()
    throws IOException
  {
    final var file =
      this.directory.resolve("nonexistent")
        .toAbsolutePath();

    final var realFile =
      CSTestDirectories.resourceOf(
        CSCommandLineTest.class,
        this.directory,
        "configuration-basic.xml"
      );

    int r = Main.mainExitless(new String[]{
      "check-configuration",
      "--file",
      file.toString()
    });
    assertEquals(1, r);

    r = Main.mainExitless(new String[]{
      "check-configuration"
    });
    assertEquals(1, r);

    r = Main.mainExitless(new String[]{
      "check-configuration",
      "--file",
      realFile.toString()
    });
    assertEquals(1, r);
  }

  @Test
  public void testShowDNSConfigurators()
    throws IOException
  {
    final int r = Main.mainExitless(new String[]{
      "show-dns-configurators"
    });
    assertEquals(0, r);
  }

  @Test
  public void testShowCertificateOutputs()
    throws IOException
  {
    final int r = Main.mainExitless(new String[]{
      "show-certificate-outputs"
    });
    assertEquals(0, r);
  }
}
