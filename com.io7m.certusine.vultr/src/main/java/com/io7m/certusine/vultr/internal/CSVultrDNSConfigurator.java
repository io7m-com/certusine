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


package com.io7m.certusine.vultr.internal;

import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.module.SimpleDeserializers;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.io7m.certusine.api.CSDNSConfiguratorType;
import com.io7m.certusine.api.CSDNSRecordNameType;
import com.io7m.certusine.api.CSTelemetryServiceType;
import com.io7m.dixmont.core.DmJsonRestrictedDeserializers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * A Vultr DNS configurator.
 */

public final class CSVultrDNSConfigurator implements CSDNSConfiguratorType
{
  private static final Logger LOG =
    LoggerFactory.getLogger(CSVultrDNSConfigurator.class);

  private final CSVultrStrings strings;
  private final HttpClient client;
  private final String apiBase;
  private final String apiKey;
  private final String domain;
  private final SimpleDeserializers serializers;
  private final JsonMapper mapper;

  /**
   * A Vultr DNS configurator.
   *
   * @param inDomain  The owning domain
   * @param inStrings String resources
   * @param inApiKey  The Vultr API key
   * @param inApiBase The API base address
   */

  public CSVultrDNSConfigurator(
    final CSVultrStrings inStrings,
    final String inDomain,
    final String inApiKey,
    final String inApiBase)
  {
    this.strings =
      Objects.requireNonNull(inStrings, "inStrings");
    this.domain =
      Objects.requireNonNull(inDomain, "inDomain");
    this.apiKey =
      Objects.requireNonNull(inApiKey, "apiKey");
    this.apiBase =
      Objects.requireNonNull(inApiBase, "apiBase")
        .replaceAll("/$", "");

    this.client =
      HttpClient.newHttpClient();

    this.serializers =
      DmJsonRestrictedDeserializers.builder()
        .allowClassName(
          "java.util.List<com.io7m.certusine.vultr.internal.CSVultrDNSRecord>")
        .allowClass(CSVultrDNSRecord.class)
        .allowClass(CSVultrDNSResponse.class)
        .allowClass(CSVultrPageLinks.class)
        .allowClass(CSVultrPageMetadata.class)
        .allowClass(List.class)
        .allowClass(Optional.class)
        .allowClass(String.class)
        .allowClass(int.class)
        .build();

    this.mapper =
      JsonMapper.builder()
        .build();

    final var simpleModule = new SimpleModule();
    simpleModule.setDeserializers(this.serializers);
    this.mapper.registerModule(simpleModule);
  }

  @Override
  public void createTXTRecord(
    final CSTelemetryServiceType telemetry,
    final CSDNSRecordNameType recordName,
    final String recordValue)
    throws IOException, InterruptedException
  {
    Objects.requireNonNull(recordName, "recordName");
    Objects.requireNonNull(recordValue, "recordValue");

    try {
      final var targetURI =
        URI.create("%s/domains/%s/records".formatted(
          this.apiBase,
          this.domain));

      LOG.debug(
        "Creating a TXT record {} = {} for domain {}",
        recordName,
        recordValue,
        this.domain
      );
      LOG.debug("POST {}", targetURI);

      final var json = """
        {
          "name": "%s",
          "type": "TXT",
          "data": "%s",
          "ttl": 600,
          "priority": 0
        }
        """.formatted(this.handleRecordName(recordName), recordValue);

      final var request =
        HttpRequest.newBuilder()
          .uri(targetURI)
          .POST(HttpRequest.BodyPublishers.ofString(json, UTF_8))
          .header("Authorization", "Bearer " + this.apiKey)
          .build();

      final var r =
        this.client.send(request, HttpResponse.BodyHandlers.ofString());

      LOG.debug("Response: {}", r.body());

      if (r.statusCode() != 201) {
        throw new IOException(
          this.strings.format("errorDNSCreate", r.statusCode())
        );
      }
    } catch (final Exception e) {
      CSTelemetryServiceType.recordExceptionAndSetError(e);
      throw e;
    }
  }

  private String handleRecordName(
    final CSDNSRecordNameType recordName)
  {
    return switch (recordName) {
      case final CSDNSRecordNameType.CSDNSRecordNameAbsolute absolute -> {
        yield absolute.stripDomainSuffix(this.domain).name();
      }
      case final CSDNSRecordNameType.CSDNSRecordNameRelative relative -> {
        yield relative.name();
      }
    };
  }

  private CSVultrDNSResponse listTXTRecordsPage(
    final Optional<String> key)
    throws IOException, InterruptedException
  {
    final var targetURI =
      key.map(cursor -> {
        return URI.create(
          "%s/domains/%s/records?per_page=500&cursor=%s"
            .formatted(this.apiBase, this.domain, cursor)
        );
      }).orElseGet(() -> {
        return URI.create(
          "%s/domains/%s/records?per_page=500"
            .formatted(this.apiBase, this.domain)
        );
      });

    final var request =
      HttpRequest.newBuilder()
        .uri(targetURI)
        .GET()
        .header("Authorization", "Bearer " + this.apiKey)
        .build();

    final var r =
      this.client.send(request, HttpResponse.BodyHandlers.ofString());

    if (r.statusCode() != 200) {
      throw new IOException(
        this.strings.format("errorDNSDelete", r.statusCode())
      );
    }

    return this.mapper.readValue(r.body(), CSVultrDNSResponse.class);
  }

  private List<CSVultrDNSRecord> listTXTRecords()
    throws IOException, InterruptedException
  {
    var response =
      this.listTXTRecordsPage(Optional.empty());

    final var records =
      new ArrayList<>(response.records());

    while (true) {
      final var next = response.meta().links().next();
      if (Objects.equals(next, "")) {
        break;
      }
      response = this.listTXTRecordsPage(Optional.of(next));
      records.addAll(response.records());
    }

    return List.copyOf(records);
  }

  @Override
  public void deleteTXTRecord(
    final CSTelemetryServiceType telemetry,
    final CSDNSRecordNameType recordName,
    final String recordValue)
    throws IOException, InterruptedException
  {
    Objects.requireNonNull(recordName, "name");
    Objects.requireNonNull(recordValue, "text");

    try {
      final var records = this.listTXTRecords();
      LOG.debug("Found {} records", records.size());

      final var matchingRecords =
        records.stream()
          .filter(r -> isMatchingTXTRecord(r, recordName, recordValue))
          .toList();

      LOG.debug("Found {} matching TXT records", matchingRecords.size());

      for (final var record : matchingRecords) {
        final var targetURI =
          URI.create(
            "%s/domains/%s/records/%s"
              .formatted(this.apiBase, this.domain, record.id())
          );

        LOG.debug("DELETE {}", targetURI);

        final var request =
          HttpRequest.newBuilder()
            .uri(targetURI)
            .DELETE()
            .header("Authorization", "Bearer " + this.apiKey)
            .build();

        final var r =
          this.client.send(request, HttpResponse.BodyHandlers.ofString());

        if (r.statusCode() != 204) {
          throw new IOException(
            this.strings.format("errorDNSDelete", r.statusCode())
          );
        }
      }
    } catch (final Exception e) {
      CSTelemetryServiceType.recordExceptionAndSetError(e);
      throw e;
    }
  }

  private static boolean isMatchingTXTRecord(
    final CSVultrDNSRecord r,
    final CSDNSRecordNameType recordName,
    final String recordValue)
  {
    if (!Objects.equals(r.type(), "TXT")) {
      return false;
    }

    if (!Objects.equals(r.name(), recordName.name())) {
      return false;
    }

    final var valRecord = r.data();
    final var valQuoted = "\"%s\"".formatted(recordValue);
    return Objects.equals(valRecord, valQuoted);
  }
}
