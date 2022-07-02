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

import com.io7m.certusine.api.CSAbstractNamedProvider;
import com.io7m.certusine.api.CSCertificateOutputProviderType;
import com.io7m.certusine.api.CSCertificateOutputType;
import com.io7m.certusine.api.CSConfigurationException;
import com.io7m.certusine.api.CSConfigurationParameterDescription;
import com.io7m.certusine.api.CSConfigurationParameters;
import com.io7m.certusine.looseleaf.internal.CSLLOutput;
import com.io7m.certusine.looseleaf.internal.CSLLStrings;

import java.io.IOException;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

import static java.util.Map.entry;

/**
 * Access to looseleaf.
 */

public final class CSLLOutputProvider
  extends CSAbstractNamedProvider
  implements CSCertificateOutputProviderType
{
  private static final String ENDPOINT_PARAMETER = "endpoint";
  private static final String USERNAME_PARAMETER = "username";
  private static final String PASSWORD_PARAMETER = "password";

  private final CSLLStrings strings;

  /**
   * Access to looseleaf.
   *
   * @param locale    A locale for error messages
   * @param inStrings String resources
   *
   * @throws IOException On I/O errors
   */

  public CSLLOutputProvider(
    final Locale locale,
    final CSLLStrings inStrings)
    throws IOException
  {
    super(locale);
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
    this(locale, new CSLLStrings(locale));
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
    Objects.requireNonNull(name, "name");
    Objects.requireNonNull(parameters, "parameters");

    this.checkParameters(parameters);

    final var parameterMap = parameters.parameters();

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

  @Override
  public String name()
  {
    return "looseleaf";
  }

  @Override
  public String description()
  {
    return "Write certificates to a looseleaf server.";
  }

  @Override
  public Map<String, CSConfigurationParameterDescription> parameters()
  {
    return Map.ofEntries(
      entry(
        ENDPOINT_PARAMETER,
        new CSConfigurationParameterDescription(
          ENDPOINT_PARAMETER,
          this.strings.format("parameterEndpoint"),
          "URI",
          true
        )
      ),
      entry(
        USERNAME_PARAMETER,
        new CSConfigurationParameterDescription(
          USERNAME_PARAMETER,
          this.strings.format("parameterUserName"),
          "User name",
          false
        )
      ),
      entry(
        PASSWORD_PARAMETER,
        new CSConfigurationParameterDescription(
          PASSWORD_PARAMETER,
          this.strings.format("parameterPassword"),
          "Password",
          false
        )
      )
    );
  }
}
