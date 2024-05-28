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

package com.io7m.certusine.gandi;

import com.io7m.certusine.api.CSAbstractNamedProvider;
import com.io7m.certusine.api.CSConfigurationException;
import com.io7m.certusine.api.CSConfigurationParameterDescription;
import com.io7m.certusine.api.CSConfigurationParameters;
import com.io7m.certusine.api.CSDNSConfiguratorProviderType;
import com.io7m.certusine.api.CSDNSConfiguratorType;
import com.io7m.certusine.gandi.internal.CSGandiDNSConfigurator;
import com.io7m.certusine.gandi.internal.CSGandiStrings;

import java.io.IOException;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

import static java.util.Map.entry;

/**
 * Access to the Gandi DNS API.
 */

public final class CSGandiDNSConfigurators
  extends CSAbstractNamedProvider
  implements CSDNSConfiguratorProviderType
{
  private static final String PAT_PARAMETER = "personal-access-token";
  private static final String DOMAIN_PARAMETER = "domain";
  private static final String API_BASE_PARAMETER = "api-base";
  private final CSGandiStrings strings;

  /**
   * Access to the Gandi DNS API.
   *
   * @param locale    A locale for error messages
   * @param inStrings String resources
   *
   * @throws IOException On I/O errors
   */

  public CSGandiDNSConfigurators(
    final Locale locale,
    final CSGandiStrings inStrings)
    throws IOException
  {
    super(locale);
    this.strings = Objects.requireNonNull(inStrings, "strings");
  }

  /**
   * Access to the Gandi DNS API.
   *
   * @param locale A locale for error messages
   *
   * @throws IOException On I/O errors
   */

  public CSGandiDNSConfigurators(
    final Locale locale)
    throws IOException
  {
    this(locale, new CSGandiStrings(locale));
  }

  /**
   * Access to the Gandi DNS API.
   *
   * @throws IOException On I/O errors
   */

  public CSGandiDNSConfigurators()
    throws IOException
  {
    this(Locale.getDefault());
  }

  @Override
  public CSDNSConfiguratorType create(
    final CSConfigurationParameters parameters)
    throws CSConfigurationException
  {
    Objects.requireNonNull(parameters, "parameters");

    this.checkParameters(parameters);

    final var parameterMap = parameters.parameters();

    final var apiBase =
      parameterMap.getOrDefault(
        API_BASE_PARAMETER, "https://api.gandi.net/");

    return new CSGandiDNSConfigurator(
      this.strings,
      parameterMap.get(DOMAIN_PARAMETER),
      parameterMap.get(PAT_PARAMETER),
      apiBase
    );
  }

  @Override
  public String name()
  {
    return "Gandi-v5";
  }

  @Override
  public String description()
  {
    return "Configure DNS records using the Gandi LiveDNS v5 API.";
  }

  @Override
  public Map<String, CSConfigurationParameterDescription> parameters()
  {
    return Map.ofEntries(
      entry(
        PAT_PARAMETER,
        new CSConfigurationParameterDescription(
          PAT_PARAMETER,
          this.strings.format("parameterApiPAT"),
          "API Key",
          true
        )
      ),
      entry(
        API_BASE_PARAMETER,
        new CSConfigurationParameterDescription(
          API_BASE_PARAMETER,
          this.strings.format("parameterApiBase"),
          "URI",
          false
        )
      ),
      entry(
        DOMAIN_PARAMETER,
        new CSConfigurationParameterDescription(
          DOMAIN_PARAMETER,
          this.strings.format("parameterDomain"),
          "Domain name",
          true
        )
      )
    );
  }

  @Override
  public String toString()
  {
    return "[CSGandiDNSConfigurators 0x%s]"
      .formatted(Long.toUnsignedString(this.hashCode(), 16));
  }
}
