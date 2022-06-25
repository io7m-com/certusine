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
public record CS1Domain(
  @JsonProperty(value = "Name", required = true)
  String name,
  @JsonProperty(value = "Account", required = true)
  String account,
  @JsonProperty(value = "Certificates", required = true)
  List<CS1Certificate> certificates,
  @JsonProperty(value = "Outputs", required = true)
  List<String> outputs,
  @JsonProperty(value = "DNSConfigurator", required = true)
  String dnsConfigurator)
{
  public CS1Domain
  {
    Objects.requireNonNull(name, "name");
    Objects.requireNonNull(account, "account");
    Objects.requireNonNull(certificates, "certificates");
    Objects.requireNonNull(outputs, "outputs");
    Objects.requireNonNull(dnsConfigurator, "dnsConfigurator");
  }
}
