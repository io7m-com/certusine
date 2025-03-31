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


package com.io7m.certusine.hetzner.internal;

import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.module.SimpleDeserializers;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.io7m.certusine.api.CSDNSConfiguratorType;
import com.io7m.certusine.api.CSDNSRecordNameType;
import com.io7m.certusine.api.CSTelemetryServiceType;
import com.io7m.dixmont.core.DmJsonRestrictedDeserializers;
import io.opentelemetry.api.trace.Span;
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
 * A Hetzner DNS configurator.
 */

public final class CSHetznerDNSConfigurator
  implements CSDNSConfiguratorType
{
  private static final Logger LOG =
    LoggerFactory.getLogger(CSHetznerDNSConfigurator.class);

  private final CSHetznerStrings strings;
  private final HttpClient client;
  private final String apiBase;
  private final String apiKey;
  private final String domainName;
  private final String zoneId;
  private final SimpleDeserializers serializers;
  private final JsonMapper mapper;

  /**
   * A Hetzner DNS configurator.
   *
   * @param inZone       The owning zone ID
   * @param inDomainName The domain name
   * @param inStrings    String resources
   * @param inApiKey     The Hetzner API key
   * @param inApiBase    The API base address
   */

  public CSHetznerDNSConfigurator(
    final CSHetznerStrings inStrings,
    final String inDomainName,
    final String inZone,
    final String inApiKey,
    final String inApiBase)
  {
    this.strings =
      Objects.requireNonNull(inStrings, "inStrings");
    this.domainName =
      Objects.requireNonNull(inDomainName, "inDomainName");
    this.zoneId =
      Objects.requireNonNull(inZone, "inZone");
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
          "java.util.List<com.io7m.certusine.hetzner.internal.CSHetznerDNSRecord>")
        .allowClass(List.class)
        .allowClass(Optional.class)
        .allowClass(String.class)
        .allowClass(int.class)
        .allowClass(CSHetznerDNSRecord.class)
        .allowClass(CSHetznerDNSRecordResponse.class)
        .allowClass(CSHetznerDNSRecordsResponse.class)
        .build();

    this.mapper =
      JsonMapper.builder()
        .build();

    final var simpleModule = new SimpleModule();
    simpleModule.setDeserializers(this.serializers);
    this.mapper.registerModule(simpleModule);
    this.mapper.registerModule(new Jdk8Module());
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

    final var span =
      telemetry.tracer()
        .spanBuilder("CreateTXTRecord")
        .startSpan();

    try (var ignored = span.makeCurrent()) {
      this.createTXTRecordInSpan(telemetry, recordName, recordValue);
    } finally {
      span.end();
    }
  }

  private void createTXTRecordInSpan(
    final CSTelemetryServiceType telemetry,
    final CSDNSRecordNameType recordName,
    final String recordValue)
    throws IOException, InterruptedException
  {
    try {
      final var records =
        this.listTXTRecords(telemetry);
      LOG.debug("Found {} records", records.size());

      final var matchingRecords =
        records.stream()
          .filter(r -> isMatchingTXTRecord(r, recordName, recordValue))
          .findFirst();

      if (matchingRecords.isPresent()) {
        LOG.debug(
          "A TXT record {} = {} for domain {} already exists.",
          recordName,
          recordValue,
          this.zoneId
        );
        return;
      }

      final var targetURI =
        URI.create("%s/records".formatted(this.apiBase));

      LOG.debug(
        "Creating a TXT record {} = {} for domain {}",
        recordName,
        recordValue,
        this.zoneId
      );
      LOG.debug("POST {}", targetURI);

      final var json = """
        {
          "name": "%s",
          "type": "TXT",
          "value": "%s",
          "ttl": 600,
          "zone_id": "%s"
        }
        """.formatted(
        this.handleRecordName(recordName),
        recordValue,
        this.zoneId
      );

      final var request =
        HttpRequest.newBuilder()
          .uri(targetURI)
          .POST(HttpRequest.BodyPublishers.ofString(json, UTF_8))
          .header("Auth-API-Token", this.apiKey)
          .build();

      final var span = Span.current();
      span.setAttribute("certusine.hetzner.create_txt.request", json);
      span.setAttribute(
        "certusine.hetzner.create_txt.uri",
        targetURI.toString());

      final var r =
        this.client.send(request, HttpResponse.BodyHandlers.ofString());

      LOG.debug("Response: {}", r.body());

      span.setAttribute(
        "certusine.hetzner.create_txt.http_response",
        r.statusCode()
      );
      span.setAttribute(
        "certusine.hetzner.create_txt.http_response_text",
        r.body()
      );

      /*
       * Everything else is actually an error.
       */

      if (r.statusCode() != 200) {
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
        yield absolute.stripDomainSuffix(this.domainName).name();
      }
      case final CSDNSRecordNameType.CSDNSRecordNameRelative relative -> {
        yield relative.name();
      }
    };
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

    final var span =
      telemetry.tracer()
        .spanBuilder("DeleteTXTRecord")
        .startSpan();

    try (var ignored = span.makeCurrent()) {
      this.deleteTXTRecordInSpan(telemetry, recordName, recordValue);
    } finally {
      span.end();
    }
  }

  private List<CSHetznerDNSRecord> listTXTRecords(
    final CSTelemetryServiceType telemetry)
    throws IOException, InterruptedException
  {
    final var span =
      telemetry.tracer()
        .spanBuilder("ListTXTRecords")
        .startSpan();

    try (var ignored = span.makeCurrent()) {
      return this.listTXTRecordsInSpan();
    } finally {
      span.end();
    }
  }

  private List<CSHetznerDNSRecord> listTXTRecordsInSpan()
    throws IOException, InterruptedException
  {
    int page = 1;

    final var records = new ArrayList<CSHetznerDNSRecord>();
    while (true) {
      final var targetURI =
        URI.create("%s/records?zone_id=%s&page=%s".formatted(
          this.apiBase,
          this.zoneId,
          Integer.valueOf(page)
        ));

      final var span = Span.current();
      span.setAttribute("certusine.hetzner.list_txt.uri", targetURI.toString());

      final var request =
        HttpRequest.newBuilder()
          .uri(targetURI)
          .GET()
          .header("Auth-API-Token", this.apiKey)
          .build();

      final var r =
        this.client.send(request, HttpResponse.BodyHandlers.ofString());

      span.setAttribute(
        "certusine.hetzner.list_txt.http_response",
        r.statusCode());
      if (r.statusCode() != 200) {
        throw new IOException(
          this.strings.format("errorDNSList", r.statusCode())
        );
      }

      final var data =
        this.mapper.readValue(r.body(), CSHetznerDNSRecordsResponse.class);

      if (data.records().isEmpty()) {
        return List.copyOf(records);
      }

      records.addAll(data.records());
      ++page;
    }
  }

  private void deleteTXTRecordInSpan(
    final CSTelemetryServiceType telemetry,
    final CSDNSRecordNameType recordName,
    final String recordValue)
    throws IOException, InterruptedException
  {
    try {
      final var records =
        this.listTXTRecords(telemetry);
      LOG.debug("Found {} records", records.size());

      final var matchingRecords =
        records.stream()
          .filter(r -> isMatchingTXTRecord(r, recordName, recordValue))
          .toList();

      LOG.debug("Found {} matching TXT records", matchingRecords.size());

      for (final var record : matchingRecords) {
        final var targetURI =
          URI.create(
            "%s/records/%s"
              .formatted(this.apiBase, record.id().orElseThrow())
          );

        LOG.debug("DELETE {}", targetURI);

        final var span = Span.current();
        span.setAttribute(
          "certusine.hetzner.delete_txt.uri",
          targetURI.toString());

        final var request =
          HttpRequest.newBuilder()
            .uri(targetURI)
            .DELETE()
            .header("Auth-API-Token", this.apiKey)
            .build();

        final var r =
          this.client.send(request, HttpResponse.BodyHandlers.ofString());

        span.setAttribute(
          "certusine.hetzner.delete_txt.http_response",
          r.statusCode()
        );

        if (r.statusCode() != 200) {
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

  private boolean isMatchingTXTRecord(
    final CSHetznerDNSRecord r,
    final CSDNSRecordNameType recordName,
    final String recordValue)
  {
    if (r.id().isEmpty()) {
      traceNoMatch(r, recordName, recordValue);
      return false;
    }
    if (!Objects.equals(r.type(), "TXT")) {
      traceNoMatch(r, recordName, recordValue);
      return false;
    }
    if (!Objects.equals(r.name(), this.handleRecordName(recordName))) {
      traceNoMatch(r, recordName, recordValue);
      return false;
    }
    if (!Objects.equals(r.valueWithoutQuoting(), recordValue)) {
      traceNoMatch(r, recordName, recordValue);
      return false;
    }

    LOG.trace("Record {} matches {} = {}", r, recordName, recordValue);
    return true;
  }

  private static void traceNoMatch(
    final CSHetznerDNSRecord r,
    final CSDNSRecordNameType recordName,
    final String recordValue)
  {
    LOG.trace("Record {} doesn't match {} = {}", r, recordName, recordValue);
  }
}
