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

package com.io7m.certusine.vanilla.internal.store;

import com.io7m.certusine.api.CSTelemetryServiceType;
import com.io7m.certusine.certstore.api.CSCertificateStoreFactoryType;
import com.io7m.certusine.certstore.api.CSCertificateStoreType;
import com.io7m.jmulticlose.core.CloseableCollection;
import com.io7m.trasco.api.TrArguments;
import com.io7m.trasco.api.TrEventExecutingSQL;
import com.io7m.trasco.api.TrEventType;
import com.io7m.trasco.api.TrEventUpgrading;
import com.io7m.trasco.api.TrExecutorConfiguration;
import com.io7m.trasco.api.TrSchemaRevisionSet;
import com.io7m.trasco.vanilla.TrExecutors;
import com.io7m.trasco.vanilla.TrSchemaRevisionSetParsers;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.StatusCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sqlite.SQLiteConfig;
import org.sqlite.SQLiteDataSource;
import org.sqlite.SQLiteErrorCode;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;

import static com.io7m.trasco.api.TrExecutorUpgrade.PERFORM_UPGRADES;
import static java.math.BigInteger.valueOf;

/**
 * The default SQLite server database implementation.
 */

public final class CSCertificateStoreSQLiteFactory
  implements CSCertificateStoreFactoryType
{
  private static final Logger LOG =
    LoggerFactory.getLogger(CSCertificateStoreSQLiteFactory.class);

  private static final String DATABASE_APPLICATION_ID =
    "com.io7m.certusine";
  private static final int APPLICATION_ID =
    0x4352_5455;

  /**
   * The default postgres server database implementation.
   */

  public CSCertificateStoreSQLiteFactory()
  {

  }

  private static void schemaVersionSet(
    final BigInteger version,
    final Connection connection)
    throws SQLException
  {
    final String statementText;
    if (Objects.equals(version, BigInteger.ZERO)) {
      statementText = "insert into schema_version (version_application_id, version_number) values (?, ?)";
      try (var statement =
             connection.prepareStatement(statementText)) {
        statement.setString(1, DATABASE_APPLICATION_ID);
        statement.setLong(2, version.longValueExact());
        statement.execute();
      }
    } else {
      statementText = "update schema_version set version_number = ?";
      try (var statement =
             connection.prepareStatement(statementText)) {
        statement.setLong(1, version.longValueExact());
        statement.execute();
      }
    }
  }

  private static Optional<BigInteger> schemaVersionGet(
    final Connection connection)
    throws SQLException
  {
    Objects.requireNonNull(connection, "connection");

    try {
      final var statementText =
        "SELECT version_application_id, version_number FROM schema_version";
      LOG.debug("execute: {}", statementText);

      try (var statement = connection.prepareStatement(statementText)) {
        try (var result = statement.executeQuery()) {
          if (!result.next()) {
            throw new SQLException("schema_version table is empty!");
          }
          final var applicationCA =
            result.getString(1);
          final var version =
            result.getLong(2);

          if (!Objects.equals(applicationCA, DATABASE_APPLICATION_ID)) {
            throw new SQLException(
              String.format(
                "Database application ID is %s but should be %s",
                applicationCA,
                DATABASE_APPLICATION_ID
              )
            );
          }

          return Optional.of(valueOf(version));
        }
      }
    } catch (final SQLException e) {
      if (e.getErrorCode() == SQLiteErrorCode.SQLITE_ERROR.code) {
        connection.rollback();
        return Optional.empty();
      }
      throw e;
    }
  }

  private static CSCertificateStoreSQLite connect(
    final CSTelemetryServiceType telemetry,
    final Path file)
  {
    final var url = new StringBuilder(128);
    url.append("jdbc:sqlite:");
    url.append(file);

    final var config = new SQLiteConfig();
    config.setApplicationId(APPLICATION_ID);
    config.enforceForeignKeys(true);

    final var dataSource = new SQLiteDataSource(config);
    dataSource.setUrl(url.toString());
    return new CSCertificateStoreSQLite(telemetry, dataSource);
  }

  private static void createOrUpgrade(
    final CSTelemetryServiceType telemetry,
    final Path file,
    final Consumer<String> startupMessages)
    throws IOException
  {
    final var resources = CloseableCollection.create(() -> {
      return new IOException("Closing a resource failed.");
    });

    final var span =
      telemetry.tracer()
        .spanBuilder("DatabaseSetup")
        .startSpan();

    final var arguments =
      new TrArguments(Map.of());

    try (var ignored0 = span.makeCurrent()) {
      try (var ignored1 = resources) {
        final var url = new StringBuilder(128);
        url.append("jdbc:sqlite:");
        url.append(file);

        final var config = new SQLiteConfig();
        config.setApplicationId(APPLICATION_ID);
        config.enforceForeignKeys(true);

        final var dataSource = new SQLiteDataSource(config);
        dataSource.setUrl(url.toString());

        final var parsers = new TrSchemaRevisionSetParsers();
        final TrSchemaRevisionSet revisions;
        try (var stream = CSCertificateStoreSQLiteFactory.class.getResourceAsStream(
          "/com/io7m/certusine/vanilla/internal/Database.xml")) {
          revisions = parsers.parse(URI.create("urn:source"), stream);
        }

        try (var connection = dataSource.getConnection()) {
          connection.setAutoCommit(false);

          new TrExecutors().create(
            new TrExecutorConfiguration(
              CSCertificateStoreSQLiteFactory::schemaVersionGet,
              CSCertificateStoreSQLiteFactory::schemaVersionSet,
              event -> publishTrEvent(startupMessages, event),
              revisions,
              PERFORM_UPGRADES,
              arguments,
              connection
            )
          ).execute();
          connection.commit();
        }
      } catch (final IOException e) {
        failSpan(e);
        throw e;
      } catch (final Exception e) {
        failSpan(e);
        throw new IOException(e);
      }
    }
  }

  private static void failSpan(
    final Exception e)
  {
    final Span span = Span.current();
    span.recordException(e);
    span.setStatus(StatusCode.ERROR);
  }

  private static void publishEvent(
    final Consumer<String> startupMessages,
    final String message)
  {
    try {
      LOG.trace("{}", message);
      startupMessages.accept(message);

      final var span = Span.current();
      span.addEvent(message);
    } catch (final Exception e) {
      LOG.error("Ignored consumer exception: ", e);
    }
  }

  private static void publishTrEvent(
    final Consumer<String> startupMessages,
    final TrEventType event)
  {
    switch (event) {
      case final TrEventExecutingSQL sql -> {
        publishEvent(
          startupMessages,
          String.format("Executing SQL: %s", sql.statement())
        );
        return;
      }
      case final TrEventUpgrading upgrading -> {
        publishEvent(
          startupMessages,
          String.format(
            "Upgrading database from version %s -> %s",
            upgrading.fromVersion(),
            upgrading.toVersion())
        );
        return;
      }
    }
  }

  @Override
  public CSCertificateStoreType open(
    final CSTelemetryServiceType telemetry,
    final Path file)
    throws IOException
  {
    Objects.requireNonNull(telemetry, "telemetry");
    Objects.requireNonNull(file, "file");

    createOrUpgrade(telemetry, file, message -> {

    });
    return connect(telemetry, file);
  }

  @Override
  public String description()
  {
    return "SQLite certificate store.";
  }

  @Override
  public String toString()
  {
    return "[CSCertificateStoreSQLiteFactory 0x%s]"
      .formatted(Long.toUnsignedString(this.hashCode(), 16));
  }
}
