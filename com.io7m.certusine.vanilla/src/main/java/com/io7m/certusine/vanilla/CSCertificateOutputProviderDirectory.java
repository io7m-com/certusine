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

package com.io7m.certusine.vanilla;

import com.io7m.anethum.common.ParseSeverity;
import com.io7m.anethum.common.ParseStatus;
import com.io7m.certusine.api.CSCertificateOutputProviderType;
import com.io7m.certusine.api.CSCertificateOutputType;
import com.io7m.certusine.api.CSConfigurationException;
import com.io7m.certusine.api.CSConfigurationParameters;
import com.io7m.certusine.vanilla.internal.CSCertificateOutputDirectory;
import com.io7m.certusine.vanilla.internal.CSStrings;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * A directory-based certificate output.
 */

public final class CSCertificateOutputProviderDirectory
  implements CSCertificateOutputProviderType
{
  private static final String PATH_PARAMETER = "path";

  private static final List<String> REQUIRED_PARAMETERS =
    List.of(PATH_PARAMETER);

  private final CSStrings strings;

  /**
   * A directory-based certificate output.
   *
   * @param inStrings String resources
   */

  public CSCertificateOutputProviderDirectory(
    final CSStrings inStrings)
  {
    this.strings = Objects.requireNonNull(inStrings, "strings");
  }

  /**
   * A directory-based certificate output.
   *
   * @param locale A locale for error messages
   *
   * @throws IOException On I/O errors
   */

  public CSCertificateOutputProviderDirectory(
    final Locale locale)
    throws IOException
  {
    this(new CSStrings(locale));
  }

  /**
   * A directory-based certificate output.
   *
   * @throws IOException On I/O errors
   */

  public CSCertificateOutputProviderDirectory()
    throws IOException
  {
    this(Locale.getDefault());
  }

  @Override
  public String name()
  {
    return "directory";
  }

  @Override
  public CSCertificateOutputType create(
    final String name,
    final CSConfigurationParameters parameters)
    throws CSConfigurationException
  {
    Objects.requireNonNull(name, "name");
    Objects.requireNonNull(parameters, "parameters");

    final var errors = new ArrayList<ParseStatus>();
    final var parameterMap = parameters.parameters();

    for (final var required : REQUIRED_PARAMETERS) {
      if (!parameterMap.containsKey(required)) {
        errors.add(
          ParseStatus.builder()
            .setSeverity(ParseSeverity.PARSE_ERROR)
            .setMessage(this.strings.format(
              "errorMissingRequiredParameter",
              required, REQUIRED_PARAMETERS))
            .setLexical(parameters.lexical())
            .setErrorCode("error-parameter-required")
            .build()
        );
      }
    }

    if (errors.isEmpty()) {
      return new CSCertificateOutputDirectory(
        name,
        parameters.baseDirectory().resolve(parameterMap.get(PATH_PARAMETER))
      );
    }

    throw new CSConfigurationException(
      errors, this.strings.format("errorOutputConfiguration")
    );
  }
}
