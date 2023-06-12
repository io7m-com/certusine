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

import ch.qos.logback.classic.Level;
import com.io7m.anethum.api.ParseStatus;
import com.io7m.anethum.api.ParsingException;
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

import static com.io7m.anethum.api.ParseSeverity.PARSE_WARNING;
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

    final var root =
      (ch.qos.logback.classic.Logger)
        LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    root.setLevel(Level.TRACE);
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
        "configuration-basic.xml"
      );

    final var configuration =
      this.parsers.parseFileWithContext(
        this.directory,
        file,
        this::onStatus
      );

    assertEquals(1, configuration.domains().size());

    assertTrue(
      this.statusLog.stream()
        .allMatch(status -> status.message().contains("contains the domain name \"example.com\"; this is probably a mistake!"))
    );
    assertTrue(
      this.statusLog.stream()
        .allMatch(status -> status.severity() == PARSE_WARNING)
    );
  }

  /**
   * A configuration file containing validation errors fails.
   *
   * @throws Exception On errors
   */

  @Test
  public void testParseErrors0()
    throws Exception
  {
    final var file =
      CSTestDirectories.resourceOf(
        CSConfigurationParserTest.class,
        this.directory,
        "configuration-errors.xml"
      );

    final var ex =
      assertThrows(ParsingException.class, () -> {
        this.parsers.parseFileWithContext(
          this.directory,
          file,
          this::onStatus
        );
      });

    final var requiredCodes = Set.of(
      "error-parse",
      "error-xml-validation"
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

    assertTrue(this.statusLog.size() > 6);
  }

  /**
   * A configuration file containing validation errors fails.
   *
   * @throws Exception On errors
   */

  @Test
  public void testParseErrors1()
    throws Exception
  {
    final var file =
      CSTestDirectories.resourceOf(
        CSConfigurationParserTest.class,
        this.directory,
        "configuration-error-private-key-corrupt.xml"
      );

    final var ex =
      assertThrows(ParsingException.class, () -> {
        this.parsers.parseFileWithContext(
          this.directory,
          file,
          this::onStatus
        );
      });

    final var requiredCodes = Set.of(
      "error-parse",
      "error-private-key-corrupt"
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

    assertTrue(this.statusLog.size() > 2);
  }

  /**
   * A configuration file containing validation errors fails.
   *
   * @throws Exception On errors
   */

  @Test
  public void testParseErrors2()
    throws Exception
  {
    final var file =
      CSTestDirectories.resourceOf(
        CSConfigurationParserTest.class,
        this.directory,
        "configuration-error-public-key-corrupt.xml"
      );

    final var ex =
      assertThrows(ParsingException.class, () -> {
        this.parsers.parseFileWithContext(
          this.directory,
          file,
          this::onStatus
        );
      });

    final var requiredCodes = Set.of(
      "error-parse",
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

    assertTrue(this.statusLog.size() > 2);
  }

  /**
   * A configuration file containing validation errors fails.
   *
   * @throws Exception On errors
   */

  @Test
  public void testParseErrors3()
    throws Exception
  {
    final var file =
      CSTestDirectories.resourceOf(
        CSConfigurationParserTest.class,
        this.directory,
        "configuration-error-public-key-missing.xml"
      );

    final var ex =
      assertThrows(ParsingException.class, () -> {
        this.parsers.parseFileWithContext(
          this.directory,
          file,
          this::onStatus
        );
      });

    final var requiredCodes = Set.of(
      "error-parse",
      "error-io-file"
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

    assertTrue(this.statusLog.size() > 2);
  }

  /**
   * A configuration file containing validation errors fails.
   *
   * @throws Exception On errors
   */

  @Test
  public void testParseErrors4()
    throws Exception
  {
    final var file =
      CSTestDirectories.resourceOf(
        CSConfigurationParserTest.class,
        this.directory,
        "configuration-error-private-key-missing.xml"
      );

    final var ex =
      assertThrows(ParsingException.class, () -> {
        this.parsers.parseFileWithContext(
          this.directory,
          file,
          this::onStatus
        );
      });

    final var requiredCodes = Set.of(
      "error-parse",
      "error-io-file"
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

    assertTrue(this.statusLog.size() > 2);
  }

  /**
   * A configuration file containing validation errors fails.
   *
   * @throws Exception On errors
   */

  @Test
  public void testParseErrors5()
    throws Exception
  {
    final var file =
      CSTestDirectories.resourceOf(
        CSConfigurationParserTest.class,
        this.directory,
        "configuration-error-certificate-name.xml"
      );

    final var ex =
      assertThrows(ParsingException.class, () -> {
        this.parsers.parseFileWithContext(
          this.directory,
          file,
          this::onStatus
        );
      });

    final var requiredCodes = Set.of(
      "error-parse",
      "error-certificate-name-invalid"
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

    assertTrue(this.statusLog.size() > 1);
  }

  /**
   * A configuration file that isn't XML fails.
   *
   * @throws Exception On errors
   */

  @Test
  public void testParseNotXML()
    throws Exception
  {
    final var ex =
      assertThrows(ParsingException.class, () -> {
        this.parsers.parseFileWithContext(
          this.directory,
          this.fakeTxt,
          this::onStatus
        );
      });

    final var requiredCodes = Set.of(
      "error-jaxb",
      "error-xml-validation"
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

    assertEquals(2, this.statusLog.size());
  }

  /**
   * A configuration file containing warnings succeeds.
   *
   * @throws Exception On errors
   */

  @Test
  public void testParseWarnings0()
    throws Exception
  {
    final var file =
      CSTestDirectories.resourceOf(
        CSConfigurationParserTest.class,
        this.directory,
        "configuration-warn-domain.xml"
      );

    this.parsers.parseFileWithContext(
      this.directory,
      file,
      this::onStatus
    );

    final var requiredCodes = Set.of(
      "warn-host-contains-domain"
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
