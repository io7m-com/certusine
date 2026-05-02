/*
 * Copyright © 2026 Mark Raynsford <code@io7m.com> https://www.io7m.com
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
import org.apache.commons.text.StringEscapeUtils;
import tools.jackson.databind.annotation.JsonDeserialize;

/**
 * The Hetzner DNS record value.
 *
 * @param value   The value
 * @param comment The comment
 *
 * @see "https://docs.hetzner.cloud/reference/cloud#tag/zones"
 */

@JsonDeserialize
@JsonIgnoreProperties(ignoreUnknown = true)
record CSHetznerRecordValue(
  @JsonProperty(value = "value")
  String value,
  @JsonProperty(value = "comment")
  String comment)
{
  /**
   * @return The value of the record without quoting
   */

  public String valueWithoutQuoting()
  {
    var x = this.value;
    if (x.startsWith("\"") && x.endsWith("\"")) {
      x = x.substring(1, x.length() - 1);
      return StringEscapeUtils.unescapeJava(x);
    }
    return x;
  }
}
