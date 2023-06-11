/*
 * Copyright © 2023 Mark Raynsford <code@io7m.com> https://www.io7m.com
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

package com.io7m.certusine.cmdline;

import com.io7m.certusine.api.CSVersion;
import com.io7m.certusine.cmdline.internal.CSCheckConfiguration;
import com.io7m.certusine.cmdline.internal.CSGenerateKeyPair;
import com.io7m.certusine.cmdline.internal.CSLooseleafDownload;
import com.io7m.certusine.cmdline.internal.CSRenew;
import com.io7m.certusine.cmdline.internal.CSShowCertificateOutputs;
import com.io7m.certusine.cmdline.internal.CSShowDNSConfigurators;
import com.io7m.quarrel.core.QApplication;
import com.io7m.quarrel.core.QApplicationMetadata;
import com.io7m.quarrel.core.QApplicationType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Main command line entry point.
 */

public final class Main implements Runnable
{
  private static final Logger LOG =
    LoggerFactory.getLogger(Main.class);

  private final List<String> args;
  private final QApplicationType application;
  private int exitCode;

  /**
   * The main entry point.
   *
   * @param inArgs Command-line arguments
   */

  public Main(
    final String[] inArgs)
  {
    this.args =
      Objects.requireNonNull(List.of(inArgs), "Command line arguments");

    final var metadata =
      new QApplicationMetadata(
        "certusine",
        "com.io7m.certusine",
        CSVersion.MAIN_VERSION,
        CSVersion.MAIN_BUILD,
        "The certusine ACME client.",
        Optional.of(URI.create("https://www.io7m.com/software/certusine/"))
      );

    final var builder = QApplication.builder(metadata);
    builder.allowAtSyntax(true);
    builder.addCommand(new CSCheckConfiguration());
    builder.addCommand(new CSGenerateKeyPair());
    builder.addCommand(new CSLooseleafDownload());
    builder.addCommand(new CSRenew());
    builder.addCommand(new CSShowCertificateOutputs());
    builder.addCommand(new CSShowDNSConfigurators());

    this.application = builder.build();
    this.exitCode = 0;
  }

  /**
   * The main entry point.
   *
   * @param args Command line arguments
   */

  public static void main(
    final String[] args)
  {
    System.exit(mainExitless(args));
  }

  /**
   * The main (exitless) entry point.
   *
   * @param args Command line arguments
   *
   * @return The exit code
   */

  public static int mainExitless(
    final String[] args)
  {
    final Main cm = new Main(args);
    cm.run();
    return cm.exitCode();
  }

  /**
   * @return The program exit code
   */

  public int exitCode()
  {
    return this.exitCode;
  }

  @Override
  public void run()
  {
    this.exitCode = this.application.run(LOG, this.args).exitCode();
  }

  @Override
  public String toString()
  {
    return String.format(
      "[Main 0x%s]",
      Long.toUnsignedString(System.identityHashCode(this), 16)
    );
  }
}
