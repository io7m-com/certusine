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

import com.io7m.jlexing.core.LexicalPosition;
import com.io7m.jlexing.core.LexicalType;

import java.net.URI;
import java.nio.file.Path;
import java.util.Map;
import java.util.Objects;

/**
 * A set of configuration parameters.
 *
 * @param baseDirectory The base directory
 * @param lexical       The lexical information for the configuration
 *                      parameters
 * @param parameters    The parameter map
 */

public record CSConfigurationParameters(
  Path baseDirectory,
  LexicalPosition<URI> lexical,
  Map<String, String> parameters)
  implements LexicalType<URI>
{
  /**
   * A set of configuration parameters.
   *
   * @param baseDirectory The base directory
   * @param lexical       The lexical information for the configuration
   *                      parameters
   * @param parameters    The parameter map
   */

  public CSConfigurationParameters
  {
    Objects.requireNonNull(baseDirectory, "baseDirectory");
    Objects.requireNonNull(lexical, "lexical");
    Objects.requireNonNull(parameters, "parameters");
  }
}

