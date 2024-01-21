/*
 * Copyright © 2024 Mark Raynsford <code@io7m.com> https://www.io7m.com
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

import com.io7m.certusine.api.CSCertificateName;
import com.io7m.certusine.api.CSTelemetryServiceType;
import com.io7m.certusine.certstore.api.CSCertificateStoreType;
import com.io7m.certusine.certstore.api.CSCertificateStored;
import org.sqlite.SQLiteDataSource;

import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * The SQLite store.
 */

public final class CSCertificateStoreSQLite
  implements CSCertificateStoreType
{
  private final SQLiteDataSource dataSource;
  private final CSTelemetryServiceType telemetry;

  CSCertificateStoreSQLite(
    final CSTelemetryServiceType inTelemetry,
    final SQLiteDataSource inDataSource)
  {
    this.telemetry =
      Objects.requireNonNull(inTelemetry, "telemetry");
    this.dataSource =
      Objects.requireNonNull(inDataSource, "dataSource");
  }

  private interface WithConnectionType<T>
  {
    T execute(Connection connection)
      throws SQLException;
  }

  private <T> T withConnection(
    final WithConnectionType<T> f)
    throws IOException
  {
    final var span =
      this.telemetry.tracer()
        .spanBuilder("SQLiteOperation")
        .startSpan();

    try (var ignored = span.makeCurrent()) {
      try (var connection = this.dataSource.getConnection()) {
        connection.setAutoCommit(false);
        return f.execute(connection);
      } catch (final SQLException e) {
        throw new IOException(e);
      }
    } finally {
      span.end();
    }
  }

  @Override
  public boolean isClosed()
  {
    return false;
  }

  private static final String DOMAIN_PUT = """
    INSERT INTO domains (d_name) VALUES ($1)
      ON CONFLICT DO UPDATE SET d_name = $1
        RETURNING d_id
    """;

  private static final String CERTIFICATE_PUT = """
    INSERT INTO certificates (
      c_domain,
      c_name,
      c_identifier,
      c_created_on,
      c_expires_on,
      c_pem,
      c_pem_full_chain
    ) VALUES (
      $1,
      $2,
      $3,
      $4,
      $5,
      $6,
      $7
    ) ON CONFLICT DO UPDATE SET
      c_domain         = $1,
      c_name           = $2,
      c_identifier     = $3,
      c_created_on     = $4,
      c_expires_on     = $5,
      c_pem            = $6,
      c_pem_full_chain = $7
    """;

  @Override
  public void put(
    final CSCertificateStored certificate)
    throws IOException
  {
    this.withConnection(connection -> {
      final long domainId;
      try (var st = connection.prepareStatement(DOMAIN_PUT)) {
        st.setString(1, certificate.domain());
        try (var q = st.executeQuery()) {
          domainId = q.getLong(1);
        }
      }
      try (var st = connection.prepareStatement(CERTIFICATE_PUT)) {
        st.setLong(1, domainId);
        st.setString(2, certificate.name().value());
        st.setString(3, certificate.identifier());
        st.setString(4, certificate.createdOn().toString());
        st.setString(5, certificate.expiresOn().toString());
        st.setString(6, certificate.pemEncodedCertificate());
        st.setString(7, certificate.pemEncodedCertificateFullChain());
        st.execute();
      }

      connection.commit();
      return null;
    });
  }

  private static final String CERTIFICATE_FIND = """
    SELECT
      d_name,
      c_name,
      c_created_on,
      c_expires_on,
      c_pem,
      c_pem_full_chain
    FROM certificates
      JOIN domains ON domains.d_id = certificates.c_domain
      WHERE ((domains.d_name = $1) AND (certificates.c_name = $2))
        """;

  @Override
  public Optional<CSCertificateStored> find(
    final String domain,
    final CSCertificateName name)
    throws IOException
  {
    return this.withConnection(connection -> {
      try (var st = connection.prepareStatement(CERTIFICATE_FIND)) {
        st.setString(1, domain);
        st.setString(2, name.value());

        try (var rs = st.executeQuery()) {
          while (rs.next()) {
            return Optional.of(
              new CSCertificateStored(
                rs.getString("d_name"),
                new CSCertificateName(rs.getString("c_name")),
                OffsetDateTime.parse(rs.getString("c_created_on")),
                OffsetDateTime.parse(rs.getString("c_expires_on")),
                rs.getString("c_pem"),
                rs.getString("c_pem_full_chain")
              )
            );
          }
          return Optional.empty();
        }
      }
    });
  }

  private static final String CERTIFICATE_DELETE = """
      DELETE FROM certificates WHERE
        c_domain = (SELECT d_id FROM domains WHERE d_name = $1)
    AND c_name   = $2
      """;

  @Override
  public boolean delete(
    final String domain,
    final CSCertificateName name)
    throws IOException
  {
    return this.withConnection(connection -> {
      try (var st = connection.prepareStatement(CERTIFICATE_DELETE)) {
        st.setString(1, domain);
        st.setString(2, name.value());
        final var updated = st.executeUpdate() == 1;
        connection.commit();
        return Boolean.valueOf(updated);
      }
    }).booleanValue();
  }

  private static final String CERTIFICATES_ALL = """
    SELECT
      d_name,
      c_name,
      c_created_on,
      c_expires_on,
      c_pem,
      c_pem_full_chain
    FROM certificates
    JOIN domains ON domains.d_id = certificates.c_domain
    ORDER BY (d_name, c_name)
        """;

  @Override
  public List<CSCertificateStored> all()
    throws IOException
  {
    return this.withConnection(connection -> {
      try (var st = connection.prepareStatement(CERTIFICATES_ALL)) {
        try (var rs = st.executeQuery()) {
          final var out = new ArrayList<CSCertificateStored>();
          while (rs.next()) {
            out.add(
              new CSCertificateStored(
                rs.getString("d_name"),
                new CSCertificateName(rs.getString("c_name")),
                OffsetDateTime.parse(rs.getString("c_created_on")),
                OffsetDateTime.parse(rs.getString("c_expires_on")),
                rs.getString("c_pem"),
                rs.getString("c_pem_full_chain")
              )
            );
          }
          return out;
        }
      }
    });
  }

  @Override
  public void close()
    throws IOException
  {

  }
}
