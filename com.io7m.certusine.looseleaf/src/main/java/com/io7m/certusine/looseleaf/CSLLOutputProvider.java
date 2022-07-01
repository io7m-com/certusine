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

package com.io7m.certusine.looseleaf;

import com.io7m.anethum.common.ParseSeverity;
import com.io7m.anethum.common.ParseStatus;
import com.io7m.certusine.api.CSCertificateOutputProviderType;
import com.io7m.certusine.api.CSCertificateOutputType;
import com.io7m.certusine.api.CSConfigurationException;
import com.io7m.certusine.api.CSConfigurationParameters;
import com.io7m.certusine.looseleaf.internal.CSLLCredentials;
import com.io7m.certusine.looseleaf.internal.CSLLOutput;
import com.io7m.certusine.looseleaf.internal.CSLLStrings;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * Access to looseleaf.
 */

public final class CSLLOutputProvider implements CSCertificateOutputProviderType
{
  private static final String ENDPOINT_PARAMETER = "endpoint";
  private static final String USERNAME_PARAMETER = "username";
  private static final String PASSWORD_PARAMETER = "password";

  private static final List<String> REQUIRED_PARAMETERS =
    List.of(ENDPOINT_PARAMETER, USERNAME_PARAMETER, PASSWORD_PARAMETER);

  private static final Set<String> KNOWN_PARAMETERS =
    Set.of(ENDPOINT_PARAMETER, USERNAME_PARAMETER, PASSWORD_PARAMETER);

  private final CSLLStrings strings;

  /**
   * Access to looseleaf.
   *
   * @param inStrings String resources
   */

  public CSLLOutputProvider(
    final CSLLStrings inStrings)
  {
    this.strings = Objects.requireNonNull(inStrings, "strings");
  }

  /**
   * Access to looseleaf.
   *
   * @param locale A locale for error messages
   *
   * @throws IOException On I/O errors
   */

  public CSLLOutputProvider(
    final Locale locale)
    throws IOException
  {
    this(new CSLLStrings(locale));
  }

  /**
   * Access to looseleaf.
   *
   * @throws IOException On I/O errors
   */

  public CSLLOutputProvider()
    throws IOException
  {
    this(Locale.getDefault());
  }

  @Override
  public CSCertificateOutputType create(
    final String name,
    final CSConfigurationParameters parameters)
    throws CSConfigurationException
  {
    final var errors =
      new ArrayList<ParseStatus>();
    final var parameterMap =
      parameters.parameters();

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

    for (final var pName : parameterMap.keySet()) {
      if (!KNOWN_PARAMETERS.contains(pName)) {
        errors.add(
          ParseStatus.builder()
            .setSeverity(ParseSeverity.PARSE_ERROR)
            .setMessage(this.strings.format(
              "errorUnrecognizedParameter",
              pName, KNOWN_PARAMETERS))
            .setLexical(parameters.lexical())
            .setErrorCode("error-parameter-unrecognized")
            .build()
        );
      }
    }

    if (errors.isEmpty()) {
      return new CSLLOutput(
        this.strings,
        name,
        new CSLLCredentials(
          parameterMap.get(USERNAME_PARAMETER),
          parameterMap.get(PASSWORD_PARAMETER)
        ),
        parameterMap.get(ENDPOINT_PARAMETER)
      );
    }

    throw new CSConfigurationException(
      errors, this.strings.format("errorOutputConfiguration")
    );
  }

  @Override
  public String name()
  {
    return "looseleaf";
  }
}
