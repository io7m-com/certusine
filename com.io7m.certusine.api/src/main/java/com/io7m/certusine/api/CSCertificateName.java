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

package com.io7m.certusine.api;

import java.io.Serializable;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * The type of certificate names.
 *
 * @param value The certificate name value
 */

public record CSCertificateName(String value)
  implements Serializable
{
  /**
   * The pattern that defines valid certificate names.
   */

  public static final Pattern VALID_NAME =
    Pattern.compile("[a-z0-9]([a-z0-9\\._-]*)");

  /**
   * The type of certificate names.
   *
   * @param value The certificate name value
   */

  public CSCertificateName
  {
    Objects.requireNonNull(value, "value");

    if (!VALID_NAME.matcher(value).matches()) {
      throw new IllegalArgumentException(
        "Certificate name '%s' must match %s".formatted(value, VALID_NAME)
      );
    }
  }

  @Override
  public String toString()
  {
    return this.value;
  }
}
