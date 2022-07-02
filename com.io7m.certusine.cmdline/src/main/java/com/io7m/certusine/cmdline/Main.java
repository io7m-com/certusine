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

package com.io7m.certusine.cmdline;

import com.io7m.certusine.cmdline.internal.CSCheckConfiguration;
import com.io7m.certusine.cmdline.internal.CSGenerateKeyPair;
import com.io7m.certusine.cmdline.internal.CSRenew;
import com.io7m.certusine.cmdline.internal.CSShowCertificateOutputs;
import com.io7m.certusine.cmdline.internal.CSShowDNSConfigurators;
import com.io7m.certusine.cmdline.internal.CSVersion;
import com.io7m.claypot.core.CLPApplicationConfiguration;
import com.io7m.claypot.core.CLPCommandConstructorType;
import com.io7m.claypot.core.CLPCommandType;
import com.io7m.claypot.core.Claypot;
import com.io7m.claypot.core.ClaypotType;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.security.Security;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.SortedMap;
import java.util.stream.Stream;

/**
 * Main command line entry point.
 */

public final class Main implements Runnable
{
  private static final Logger LOG = LoggerFactory.getLogger(Main.class);

  private final String[] args;
  private final ClaypotType claypot;

  /**
   * The main entry point.
   *
   * @param inArgs Command-line arguments
   */

  public Main(
    final String[] inArgs)
  {
    this.args =
      Objects.requireNonNull(inArgs, "Command line arguments");

    Security.addProvider(new BouncyCastleProvider());

    final List<CLPCommandConstructorType> commands =
      List.of(
        CSCheckConfiguration::new,
        CSGenerateKeyPair::new,
        CSRenew::new,
        CSShowCertificateOutputs::new,
        CSShowDNSConfigurators::new,
        CSVersion::new
      );

    final var configuration =
      CLPApplicationConfiguration.builder()
        .setLogger(LOG)
        .setProgramName("certusine")
        .setCommands(commands)
        .setDocumentationURI(URI.create(
          "https://www.io7m.com/software/certusine/documentation/"))
        .build();

    this.claypot = Claypot.create(configuration);
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
    return this.claypot.exitCode();
  }

  @Override
  public void run()
  {
    this.claypot.execute(this.args);
  }

  /**
   * @return The names of the available commands
   */

  public Stream<String> commandNames()
  {
    return this.commands()
      .keySet()
      .stream();
  }

  /**
   * @return The available commands
   */

  public SortedMap<String, CLPCommandType> commands()
  {
    return this.claypot.commands();
  }

  @Override
  public String toString()
  {
    return String.format(
      "[Main 0x%s]",
      Long.toUnsignedString(System.identityHashCode(this), 16)
    );
  }

  /**
   * @return The exception that caused the exit
   */

  public Optional<Exception> exitCause()
  {
    return this.claypot.exitCause();
  }
}
