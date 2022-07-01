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

import com.io7m.certusine.api.CSAbstractNamedProvider;
import com.io7m.certusine.api.CSCertificateOutputProviderType;
import com.io7m.certusine.api.CSCertificateOutputType;
import com.io7m.certusine.api.CSConfigurationException;
import com.io7m.certusine.api.CSConfigurationParameterDescription;
import com.io7m.certusine.api.CSConfigurationParameters;
import com.io7m.certusine.vanilla.internal.CSCertificateOutputDirectory;
import com.io7m.certusine.vanilla.internal.CSStrings;

import java.io.IOException;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

import static java.util.Map.entry;

/**
 * A directory-based certificate output.
 */

public final class CSCertificateOutputProviderDirectory
  extends CSAbstractNamedProvider
  implements CSCertificateOutputProviderType
{
  private static final String PATH_PARAMETER = "path";

  private static final List<String> REQUIRED_PARAMETERS =
    List.of(PATH_PARAMETER);

  private final CSStrings strings;

  /**
   * A directory-based certificate output.
   *
   * @param locale    A locale for error messages
   * @param inStrings String resources
   *
   * @throws IOException On I/O errors
   */

  public CSCertificateOutputProviderDirectory(
    final Locale locale,
    final CSStrings inStrings)
    throws IOException
  {
    super(locale);
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
    this(locale, new CSStrings(locale));
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

    this.checkParameters(parameters);

    final var parameterMap = parameters.parameters();

    return new CSCertificateOutputDirectory(
      name,
      parameters.baseDirectory().resolve(parameterMap.get(PATH_PARAMETER))
    );
  }

  @Override
  public String description()
  {
    return "Write certificates to a local directory.";
  }

  @Override
  public Map<String, CSConfigurationParameterDescription> parameters()
  {
    return Map.ofEntries(
      entry(
        PATH_PARAMETER,
        new CSConfigurationParameterDescription(
          PATH_PARAMETER,
          this.strings.format("parameterPath"),
          "Path",
          true
        )
      )
    );
  }
}
