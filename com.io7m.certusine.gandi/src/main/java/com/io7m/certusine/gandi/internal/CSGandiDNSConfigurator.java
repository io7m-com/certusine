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

import com.io7m.certusine.api.CSDNSConfiguratorType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Objects;

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
  private final String apiKey;
  private final String domain;

  /**
   * A Gandi DNS configurator.
   *
   * @param inDomain  The owning domain
   * @param inStrings String resources
   * @param inApiKey  The Gandi API key
   * @param inApiBase The API base address
   */

  public CSGandiDNSConfigurator(
    final CSGandiStrings inStrings,
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
  }

  @Override
  public void createTXTRecord(
    final String recordName,
    final String recordValue)
    throws IOException, InterruptedException
  {
    Objects.requireNonNull(recordName, "recordName");
    Objects.requireNonNull(recordValue, "recordValue");

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
    LOG.debug("POST {}", targetURI);

    final var json = """
      {
        "rrset_type": "TXT",
        "rrset_values": [
          "%s"
        ]
      }
      """.formatted(recordValue);

    final var request =
      HttpRequest.newBuilder()
        .uri(targetURI)
        .POST(HttpRequest.BodyPublishers.ofString(json, UTF_8))
        .header("Authorization", "Apikey " + this.apiKey)
        .build();

    final var r =
      this.client.send(request, HttpResponse.BodyHandlers.ofString());

    LOG.debug("response: {}", r.body());

    final var statusCode = r.statusCode();
    switch (statusCode) {
      case 200, 201 -> {

      }
      default -> {
        throw new IOException(
          this.strings.format("errorServer", statusCode)
        );
      }
    }
  }

  @Override
  public void deleteTXTRecord(
    final String recordName,
    final String recordValue)
    throws IOException, InterruptedException
  {
    Objects.requireNonNull(recordName, "recordName");
    Objects.requireNonNull(recordValue, "recordValue");

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
    LOG.debug("DELETE {}", targetURI);

    final var request =
      HttpRequest.newBuilder()
        .uri(targetURI)
        .DELETE()
        .header("Authorization", "Apikey " + this.apiKey)
        .build();

    final var r =
      this.client.send(request, HttpResponse.BodyHandlers.ofString());

    LOG.debug("response: {}", r.body());

    final var statusCode = r.statusCode();
    switch (statusCode) {
      case 200, 201 -> {

      }
      default -> {
        throw new IOException(
          this.strings.format("errorServer", statusCode)
        );
      }
    }
  }
}
