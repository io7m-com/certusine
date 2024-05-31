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


package com.io7m.certusine.vultr.internal;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import java.util.List;
import java.util.Objects;

/**
 * The Vultr DNS response.
 *
 * @param records The DNS records
 * @param meta    Paging metadata
 *
 * @see "https://www.vultr.com/api/#tag/dns/operation/list-dns-domain-records"
 */

@JsonDeserialize
public record CSVultrDNSResponse(
  @JsonProperty(value = "records")
  List<CSVultrDNSRecord> records,
  @JsonProperty(value = "meta")
  CSVultrPageMetadata meta)
{
  /**
   * The Vultr DNS response.
   *
   * @param records The DNS records
   * @param meta    Paging metadata
   *
   * @see "https://www.vultr.com/api/#tag/dns/operation/list-dns-domain-records"
   */

  public CSVultrDNSResponse
  {
    Objects.requireNonNull(records, "records");
    Objects.requireNonNull(meta, "meta");
  }
}
