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

import com.io7m.anethum.common.ParseException;
import com.io7m.anethum.common.ParseStatus;
import com.io7m.certusine.vanilla.CSConfigurationParsers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public final class CSConfigurationParserTest
{
  private static final Logger LOGGER =
    LoggerFactory.getLogger(CSConfigurationParserTest.class);

  private CSConfigurationParsers parsers;
  private Path directory;
  private ArrayList<ParseStatus> statusLog;
  private Path fakePrivate;
  private Path fakePublic;
  private Path fakeTxt;

  @BeforeEach
  public void setup()
    throws Exception
  {
    this.parsers =
      new CSConfigurationParsers();
    this.directory =
      CSTestDirectories.createTempDirectory();

    this.fakePrivate =
      CSTestDirectories.resourceOf(
          CSConfigurationParserTest.class, this.directory, "fake.pri")
        .toAbsolutePath();

    this.fakePublic =
      CSTestDirectories.resourceOf(
          CSConfigurationParserTest.class, this.directory, "fake.pub")
        .toAbsolutePath();

    this.fakeTxt =
      CSTestDirectories.resourceOf(
          CSConfigurationParserTest.class, this.directory, "fake.txt")
        .toAbsolutePath();

    this.statusLog = new ArrayList<ParseStatus>();
  }

  @AfterEach
  public void tearDown()
    throws Exception
  {
    CSTestDirectories.deleteDirectory(this.directory);
  }

  /**
   * A basic configuration file is parsed correctly.
   *
   * @throws Exception On errors
   */

  @Test
  public void testParseBasic()
    throws Exception
  {
    final var file =
      CSTestDirectories.resourceOf(
        CSConfigurationParserTest.class,
        this.directory,
        "configuration-basic.json"
      );

    final var configuration =
      this.parsers.parseFileWithContext(
        this.directory,
        file,
        this::onStatus
      );

    assertEquals(1, configuration.domains().size());
  }

  /**
   * A configuration file containing every possible kind of error fails.
   *
   * @throws Exception On errors
   */

  @Test
  public void testParseHugeErrors()
    throws Exception
  {
    final var file =
      CSTestDirectories.resourceOf(
        CSConfigurationParserTest.class,
        this.directory,
        "configuration-errors.json"
      );

    final var ex =
      assertThrows(ParseException.class, () -> {
        this.parsers.parseFileWithContext(
          this.directory,
          file,
          this::onStatus
        );
      });

    final var requiredCodes = Set.of(
      "error-account-duplicate",
      "error-dns-duplicate",
      "error-dns-provider-nonexistent",
      "error-domain-account-nonexistent",
      "error-domain-certificate-duplicate",
      "error-domain-dnsconfigurator-nonexistent",
      "error-domain-duplicate",
      "error-domain-output-nonexistent",
      "error-duration",
      "error-io-file",
      "error-output-duplicate",
      "error-output-provider-nonexistent",
      "error-parameter-duplicate",
      "error-parameter-required",
      "error-private-key-corrupt",
      "error-public-key-corrupt"
    );

    for (final var requiredCode : requiredCodes) {
      assertTrue(
        this.statusLog.stream()
          .anyMatch(p -> Objects.equals(p.errorCode(), requiredCode)),
        "Status log %s must contain the error code %s".formatted(
          this.statusLog.stream()
            .map(ParseStatus::errorCode)
            .collect(Collectors.toSet()),
          requiredCode
        )
      );
    }

    assertTrue(this.statusLog.size() > 15);
  }

  /**
   * A configuration file that isn't JSON fails.
   *
   * @throws Exception On errors
   */

  @Test
  public void testParseNotJSON()
    throws Exception
  {
    final var ex =
      assertThrows(ParseException.class, () -> {
        this.parsers.parseFileWithContext(
          this.directory,
          this.fakeTxt,
          this::onStatus
        );
      });

    final var requiredCodes = Set.of(
      "error-io"
    );

    for (final var requiredCode : requiredCodes) {
      assertTrue(
        this.statusLog.stream()
          .anyMatch(p -> Objects.equals(p.errorCode(), requiredCode)),
        "Status log %s must contain the error code %s".formatted(
          this.statusLog.stream()
            .map(ParseStatus::errorCode)
            .collect(Collectors.toSet()),
          requiredCode
        )
      );
    }

    assertEquals(1, this.statusLog.size());
  }

  private void onStatus(
    final ParseStatus parseStatus)
  {
    LOGGER.debug("{}", parseStatus);
    this.statusLog.add(parseStatus);
  }
}
