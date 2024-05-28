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


package com.io7m.certusine.gandi.internal;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.io7m.certusine.api.CSDNSConfiguratorType;
import com.io7m.certusine.api.CSDNSRecordNameType;
import com.io7m.certusine.api.CSTelemetryServiceType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * A Gandi DNS configurator.
 */

public final class CSGandiDNSConfigurator implements CSDNSConfiguratorType
{
  private static final Logger LOG =
    LoggerFactory.getLogger(CSGandiDNSConfigurator.class);

  private final CSGandiStrings strings;
  private final HttpClient client;
  private final String apiBase;
  private final String pat;
  private final String domain;
  private final ObjectMapper mapper;

  /**
   * A Gandi DNS configurator.
   *
   * @param inDomain  The owning domain
   * @param inStrings String resources
   * @param inPAT     The Gandi personal access token
   * @param inApiBase The API base address
   */

  public CSGandiDNSConfigurator(
    final CSGandiStrings inStrings,
    final String inDomain,
    final String inPAT,
    final String inApiBase)
  {
    this.strings =
      Objects.requireNonNull(inStrings, "inStrings");
    this.domain =
      Objects.requireNonNull(inDomain, "inDomain");
    this.pat =
      Objects.requireNonNull(inPAT, "apiKey");
    this.apiBase =
      Objects.requireNonNull(inApiBase, "apiBase")
        .replaceAll("/$", "");

    this.client =
      HttpClient.newHttpClient();
    this.mapper =
      new ObjectMapper();
  }

  private Optional<TXTRecord> fetchTXTRecord(
    final CSDNSRecordNameType recordName)
    throws IOException, InterruptedException
  {
    LOG.debug(
      "retrieving TXT record {} for domain {}",
      recordName,
      this.domain
    );

    final var targetURI =
      URI.create(
        "%s/v5/livedns/domains/%s/records/%s"
          .formatted(
            this.apiBase,
            this.domain,
            recordName
          )
      );

    final var request =
      HttpRequest.newBuilder()
        .uri(targetURI)
        .GET()
        .header("Authorization", "Bearer " + this.pat)
        .build();

    final var r =
      this.client.send(request, BodyHandlers.ofInputStream());

    final var statusCode = r.statusCode();
    return switch (statusCode) {
      case 404 -> {
        LOG.debug(
          "no TXT record {} exists for domain {}",
          recordName,
          this.domain);
        yield Optional.empty();
      }
      case 200 -> {
        LOG.debug(
          "a TXT record {} exists for domain {}",
          recordName,
          this.domain);
        yield this.parseTXTRecord(r.body());
      }
      default -> {
        final var exception = new IOException(
          this.strings.format("errorServer", statusCode)
        );
        CSTelemetryServiceType.recordExceptionAndSetError(exception);
        throw exception;
      }
    };
  }

  private Optional<TXTRecord> parseTXTRecord(
    final InputStream body)
    throws IOException
  {
    try {
      final var node = this.mapper.readTree(body);

      if (node instanceof final ArrayNode arrayNode) {
        if (arrayNode.isEmpty()) {
          return Optional.empty();
        }

        final var first = arrayNode.get(0);
        if (first instanceof final ObjectNode object) {
          final var values = object.get("rrset_values");
          if (values instanceof final ArrayNode existingArray) {
            final var arrayValues = new ArrayList<String>(existingArray.size());
            for (var index = 0; index < existingArray.size(); ++index) {
              arrayValues.add(existingArray.get(index).asText());
            }
            return Optional.of(new TXTRecord(List.copyOf(arrayValues)));
          }

          throw new IOException(
            this.strings.format(
              "errorParse",
              "rrset_values is not an array")
          );
        }
      }

      throw new IOException(
        this.strings.format(
          "errorParse",
          "Did not receive a parseable JSON object")
      );
    } catch (final IOException e) {
      CSTelemetryServiceType.recordExceptionAndSetError(e);
      throw e;
    }
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
        .setAttribute("certusine.record.name", recordName.name())
        .startSpan();

    try (var ignored = span.makeCurrent()) {
      final var targetURI =
        URI.create(
          "%s/v5/livedns/domains/%s/records/%s"
            .formatted(
              this.apiBase,
              this.domain,
              recordName
            )
        );

      LOG.debug(
        "creating a TXT record {} = {} for domain {}",
        recordName,
        recordValue,
        this.domain
      );

      /*
       * First, fetch any existing TXT record. If a record already exists
       * that contains the required value, then do nothing.
       */

      final var existingRecordOpt =
        this.fetchTXTRecord(recordName);

      if (existingRecordOpt.isPresent()) {
        final var existingRecord = existingRecordOpt.get();
        if (existingRecord.values.contains(recordValue)) {
          LOG.debug("a record already exists with value {}", recordValue);
          return;
        }
      }

      /*
       * We need to either create a new record with the given value, or append
       * the value to the existing record.
       */

      final var values = new ArrayList<String>();
      existingRecordOpt.ifPresent(txt -> values.addAll(txt.values));
      values.add(recordValue);

      this.postUpdate(
        targetURI,
        this.mapper.writeValueAsString(this.constructPutRequest(values))
      );
    } finally {
      span.end();
    }
  }

  private ObjectNode constructPutRequest(
    final List<String> values)
  {
    final var newRecord = this.mapper.createObjectNode();
    newRecord.put("rrset_type", "TXT");

    final var newValues = this.mapper.createArrayNode();
    for (final var value : values) {
      newValues.add(value);
    }
    newRecord.set("rrset_values", newValues);

    final var newItemsArray = this.mapper.createArrayNode();
    newItemsArray.add(newRecord);

    final var newItemsContainer = this.mapper.createObjectNode();
    newItemsContainer.set("items", newItemsArray);
    return newItemsContainer;
  }

  private void postUpdate(
    final URI targetURI,
    final String text)
    throws IOException, InterruptedException
  {
    LOG.debug("PUT {}", targetURI);

    final var request =
      HttpRequest.newBuilder()
        .uri(targetURI)
        .PUT(HttpRequest.BodyPublishers.ofString(text, UTF_8))
        .header("Authorization", "Bearer " + this.pat)
        .build();

    final var r =
      this.client.send(request, BodyHandlers.ofString());

    LOG.debug("response: {}", r.body());

    final var statusCode = r.statusCode();
    switch (statusCode) {
      case 200, 201 -> {

      }
      default -> {
        final var exception =
          new IOException(this.strings.format("errorServer", statusCode));
        CSTelemetryServiceType.recordExceptionAndSetError(exception);
        throw exception;
      }
    }
  }

  @Override
  public void deleteTXTRecord(
    final CSTelemetryServiceType telemetry,
    final CSDNSRecordNameType recordName,
    final String recordValue)
    throws IOException, InterruptedException
  {
    Objects.requireNonNull(recordName, "recordName");
    Objects.requireNonNull(recordValue, "recordValue");

    final var span =
      telemetry.tracer()
        .spanBuilder("DeleteTXTRecord")
        .setAttribute("certusine.record.name", recordName.name())
        .startSpan();

    try (var ignored = span.makeCurrent()) {
      final var targetURI =
        URI.create(
          "%s/v5/livedns/domains/%s/records/%s"
            .formatted(
              this.apiBase,
              this.domain,
              recordName
            )
        );

      LOG.debug(
        "deleting a TXT record {} = {} for domain {}",
        recordName,
        recordValue,
        this.domain
      );

      /*
       * First, fetch any existing TXT record. If a record doesn't exist,
       * then do nothing.
       */

      final var existingRecordOpt =
        this.fetchTXTRecord(recordName);

      if (existingRecordOpt.isEmpty()) {
        LOG.debug("no record exists");
        return;
      }

      /*
       * We need to either create a new record with the given value removed, or
       * delete the record entirely if the new record would be empty.
       */

      final var existingRecord = existingRecordOpt.get();
      final var newValueList = new ArrayList<>(existingRecord.values);
      newValueList.remove(recordValue);

      if (newValueList.isEmpty()) {
        this.executeDeleteRequest(targetURI);
        return;
      }

      this.postUpdate(
        targetURI,
        this.mapper.writeValueAsString(this.constructPutRequest(newValueList))
      );
    } finally {
      span.end();
    }
  }

  private void executeDeleteRequest(final URI targetURI)
    throws IOException, InterruptedException
  {
    LOG.debug("DELETE {}", targetURI);

    final var request =
      HttpRequest.newBuilder()
        .uri(targetURI)
        .DELETE()
        .header("Authorization", "Bearer " + this.pat)
        .build();

    final var r =
      this.client.send(request, BodyHandlers.ofString());

    LOG.debug("response: {}", r.body());

    final var statusCode = r.statusCode();
    switch (statusCode) {
      case 200, 201 -> {

      }
      default -> {
        final var exception =
          new IOException(this.strings.format("errorServer", statusCode));
        CSTelemetryServiceType.recordExceptionAndSetError(exception);
        throw exception;
      }
    }
  }

  private record TXTRecord(List<String> values)
  {
    TXTRecord
    {
      Objects.requireNonNull(values, "values");
    }
  }
}
