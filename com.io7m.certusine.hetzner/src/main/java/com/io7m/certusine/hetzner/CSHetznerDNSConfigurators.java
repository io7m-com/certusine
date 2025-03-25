/*
 * Copyright © 2025 Mark Raynsford <code@io7m.com> https://www.io7m.com
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


package com.io7m.certusine.hetzner;

import com.io7m.certusine.api.CSAbstractNamedProvider;
import com.io7m.certusine.api.CSConfigurationException;
import com.io7m.certusine.api.CSConfigurationParameterDescription;
import com.io7m.certusine.api.CSConfigurationParameters;
import com.io7m.certusine.api.CSDNSConfiguratorProviderType;
import com.io7m.certusine.api.CSDNSConfiguratorType;
import com.io7m.certusine.hetzner.internal.CSHetznerDNSConfigurator;
import com.io7m.certusine.hetzner.internal.CSHetznerStrings;

import java.io.IOException;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

import static java.util.Map.entry;

/**
 * Access to the Hetzner DNS API.
 */

public final class CSHetznerDNSConfigurators
  extends CSAbstractNamedProvider
  implements CSDNSConfiguratorProviderType
{
  private static final String API_KEY_PARAMETER = "api-key";
  private static final String ZONE_ID_PARAMETER = "zone-id";
  private static final String API_BASE_PARAMETER = "api-base";
  private final CSHetznerStrings strings;

  /**
   * Access to the Hetzner DNS API.
   *
   * @param locale      A locale for error messages
   * @param inStrings   String resources
   *
   * @throws IOException On I/O errors
   */

  public CSHetznerDNSConfigurators(
    final Locale locale,
    final CSHetznerStrings inStrings)
    throws IOException
  {
    super(locale);
    this.strings = Objects.requireNonNull(inStrings, "strings");
  }

  /**
   * Access to the Hetzner DNS API.
   *
   * @param locale      A locale for error messages
   *
   * @throws IOException On I/O errors
   */

  public CSHetznerDNSConfigurators(
    final Locale locale)
    throws IOException
  {
    this(locale, new CSHetznerStrings(locale));
  }

  /**
   * Access to the Hetzner DNS API.
   *
   * @throws IOException On I/O errors
   */

  public CSHetznerDNSConfigurators()
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
        API_BASE_PARAMETER,
        "https://dns.hetzner.com/api/v1/"
      );

    return new CSHetznerDNSConfigurator(
      this.strings,
      parameterMap.get(ZONE_ID_PARAMETER),
      parameterMap.get(API_KEY_PARAMETER),
      apiBase
    );
  }

  @Override
  public String name()
  {
    return "Hetzner";
  }

  @Override
  public String description()
  {
    return "Configure DNS records using the Hetzner DNS API.";
  }

  @Override
  public Map<String, CSConfigurationParameterDescription> parameters()
  {
    return Map.ofEntries(
      entry(
        API_KEY_PARAMETER,
        new CSConfigurationParameterDescription(
          API_KEY_PARAMETER,
          this.strings.format("parameterApiKey"),
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
        ZONE_ID_PARAMETER,
        new CSConfigurationParameterDescription(
          ZONE_ID_PARAMETER,
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
    return "[CSHetznerDNSConfigurators 0x%s]"
      .formatted(Long.toUnsignedString(this.hashCode(), 16));
  }
}
