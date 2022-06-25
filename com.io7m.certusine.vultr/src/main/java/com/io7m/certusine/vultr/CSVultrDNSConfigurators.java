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


package com.io7m.certusine.vultr;

import com.io7m.anethum.common.ParseSeverity;
import com.io7m.anethum.common.ParseStatus;
import com.io7m.certusine.api.CSConfigurationException;
import com.io7m.certusine.api.CSConfigurationParameters;
import com.io7m.certusine.api.CSDNSConfiguratorProviderType;
import com.io7m.certusine.api.CSDNSConfiguratorType;
import com.io7m.certusine.vultr.internal.CSVultrDNSConfigurator;
import com.io7m.certusine.vultr.internal.CSVultrStrings;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * Access to the Vultr DNS API.
 */

public final class CSVultrDNSConfigurators
  implements CSDNSConfiguratorProviderType
{
  private static final String API_KEY_PARAMETER = "api-key";
  private static final String DOMAIN_PARAMETER = "domain";

  private static final List<String> REQUIRED_PARAMETERS =
    List.of(API_KEY_PARAMETER, DOMAIN_PARAMETER);

  private final CSVultrStrings strings;

  /**
   * Access to the Vultr DNS API.
   *
   * @param inStrings String resources
   */

  public CSVultrDNSConfigurators(
    final CSVultrStrings inStrings)
  {
    this.strings = Objects.requireNonNull(inStrings, "strings");
  }

  /**
   * Access to the Vultr DNS API.
   *
   * @param locale A locale for error messages
   *
   * @throws IOException On I/O errors
   */

  public CSVultrDNSConfigurators(
    final Locale locale)
    throws IOException
  {
    this(new CSVultrStrings(locale));
  }

  /**
   * Access to the Vultr DNS API.
   *
   * @throws IOException On I/O errors
   */

  public CSVultrDNSConfigurators()
    throws IOException
  {
    this(Locale.getDefault());
  }

  @Override
  public CSDNSConfiguratorType create(
    final CSConfigurationParameters parameters)
    throws CSConfigurationException
  {
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

    final var apiBase =
      parameterMap.getOrDefault("api-base", "https://api.vultr.com/v2/");

    if (errors.isEmpty()) {
      return new CSVultrDNSConfigurator(
        this.strings,
        parameterMap.get(DOMAIN_PARAMETER),
        parameterMap.get(API_KEY_PARAMETER),
        apiBase
      );
    }

    throw new CSConfigurationException(
      errors, this.strings.format("errorDNSConfiguration")
    );
  }

  @Override
  public String name()
  {
    return "vultr";
  }
}
