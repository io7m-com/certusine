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

import java.net.URI;
import java.util.Objects;

// CHECKSTYLE:OFF

@JsonDeserialize
@JsonSerialize
public record CS1Account(
  @JsonProperty(value = "Name", required = true)
  String name,
  @JsonProperty(value = "PublicKeyPath", required = true)
  String publicKeyPath,
  @JsonProperty(value = "PrivateKeyPath", required = true)
  String privateKeyPath,
  @JsonProperty(value = "AcmeURI", required = true)
  URI acmeURI)
{
  public CS1Account
  {
    Objects.requireNonNull(name, "name");
    Objects.requireNonNull(publicKeyPath, "publicKeyPath");
    Objects.requireNonNull(privateKeyPath, "privateKeyPath");
    Objects.requireNonNull(acmeURI, "acmeURI");
  }
}
