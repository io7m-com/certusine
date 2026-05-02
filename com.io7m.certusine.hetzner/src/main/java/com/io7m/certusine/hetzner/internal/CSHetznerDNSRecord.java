/*
 * Copyright © 2025 Mark Raynsford <code@io7m.com> https://www.io7m.com
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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import tools.jackson.databind.annotation.JsonDeserialize;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * The Hetzner DNS record.
 *
 * @param zoneId  The zone ID
 * @param id      The record ID
 * @param type    The type
 * @param name    The name
 * @param records The record values
 * @param ttl     The time-to-live
 *
 * @see "https://docs.hetzner.cloud/reference/cloud#tag/zones"
 */

@JsonDeserialize
@JsonIgnoreProperties(ignoreUnknown = true)
public record CSHetznerDNSRecord(
  @JsonProperty(value = "zone")
  String zoneId,
  @JsonProperty(value = "id", required = false)
  Optional<String> id,
  @JsonProperty(value = "type")
  String type,
  @JsonProperty(value = "name")
  String name,
  @JsonProperty(value = "records")
  List<CSHetznerRecordValue> records,
  @JsonProperty(value = "ttl")
  int ttl)
{

  /**
   * The Hetzner DNS record.
   *
   * @param zoneId  The zone ID
   * @param id      The record ID
   * @param type    The type
   * @param name    The name
   * @param records The records
   * @param ttl     The time-to-live
   *
   * @see "https://dns.hetzner.com/api-docs#operation/CreateRecord"
   */

  public CSHetznerDNSRecord
  {
    Objects.requireNonNull(zoneId, "zoneId");
    Objects.requireNonNull(id, "id");
    Objects.requireNonNull(type, "type");
    Objects.requireNonNull(name, "name");
    Objects.requireNonNull(records, "records");
  }
}
