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

import java.util.Objects;

/**
 * A DNS record name.
 */

public sealed interface CSDNSRecordNameType
{
  /**
   * @return The record name text
   */

  String name();

  /**
   * An absolute record name (ends with '.').
   *
   * @param name The name
   */

  record CSDNSRecordNameAbsolute(
    String name)
    implements CSDNSRecordNameType
  {
    /**
     * An absolute record name (ends with '.').
     */

    public CSDNSRecordNameAbsolute
    {
      Objects.requireNonNull(name, "name");

      if (!name.endsWith(".")) {
        throw new IllegalArgumentException(
          "Absolute name '%s' must end with '.'".formatted(name));
      }
    }

    @Override
    public String toString()
    {
      return this.name;
    }
  }

  /**
   * A relative record name (does not end with '.').
   *
   * @param name The name
   */

  record CSDNSRecordNameRelative(
    String name)
    implements CSDNSRecordNameType
  {
    /**
     * A relative record name (does not end with '.').
     */

    public CSDNSRecordNameRelative
    {
      Objects.requireNonNull(name, "name");

      if (name.endsWith(".")) {
        throw new IllegalArgumentException(
          "Relative name '%s' must not end with '.'".formatted(name));
      }
    }

    @Override
    public String toString()
    {
      return this.name;
    }
  }
}
