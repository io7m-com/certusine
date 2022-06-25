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

package com.io7m.certusine.vanilla.internal.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import java.util.List;
import java.util.Objects;

// CHECKSTYLE:OFF

@JsonDeserialize
@JsonSerialize
public record CS1Configuration(
  @JsonProperty(value = "%Schema", required = false)
  String schema,
  @JsonProperty(value = "Options", required = true)
  CS1Options options,
  @JsonProperty(value = "Accounts", required = true)
  List<CS1Account> accounts,
  @JsonProperty(value = "Outputs", required = true)
  List<CS1Output> outputs,
  @JsonProperty(value = "DNSConfigurators", required = true)
  List<CS1DNSConfigurator> dnsConfigurators,
  @JsonProperty(value = "Domains", required = true)
  List<CS1Domain> domains)
{
  public CS1Configuration
  {
    Objects.requireNonNull(accounts, "accounts");
    Objects.requireNonNull(options, "options");
    Objects.requireNonNull(outputs, "outputs");
    Objects.requireNonNull(dnsConfigurators, "dnsConfigurators");
    Objects.requireNonNull(domains, "domains");
  }
}
