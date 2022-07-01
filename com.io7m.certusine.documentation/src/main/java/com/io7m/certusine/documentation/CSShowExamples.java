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

package com.io7m.certusine.documentation;

import com.io7m.certusine.cmdline.Main;

import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.TRUNCATE_EXISTING;
import static java.nio.file.StandardOpenOption.WRITE;

/**
 * Generate example text.
 */

public final class CSShowExamples
{
  private CSShowExamples()
  {

  }

  /**
   * Command-line entry point.
   *
   * @param args The arguments
   *
   * @throws Exception On errors
   */

  public static void main(
    final String[] args)
    throws Exception
  {
    final var commands = List.of(
      "check-configuration",
      "generate-keypair",
      "renew",
      "show-certificate-outputs",
      "show-dns-configurators",
      "version"
    );

    for (final var command : commands) {
      final var path =
        Paths.get("c-" + command + ".txt");

      try (var output =
             Files.newOutputStream(path, CREATE, WRITE, TRUNCATE_EXISTING)) {
        System.setOut(new PrintStream(output, true, UTF_8));
        System.setErr(new PrintStream(output, true, UTF_8));
        Main.mainExitless(new String[]{
          "help",
          command
        });
      }
    }
  }
}
