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

import com.io7m.anethum.common.ParseStatus;
import com.io7m.certusine.api.CSCertificateOutputProviderType;
import com.io7m.certusine.api.CSConfigurationParserType;
import com.io7m.certusine.api.CSConfigurationParsersType;
import com.io7m.certusine.api.CSDNSConfiguratorProviderType;
import com.io7m.certusine.api.CSNamedProviderType;
import com.io7m.certusine.vanilla.internal.CSConfigurationParser;
import com.io7m.certusine.vanilla.internal.CSStrings;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.ServiceLoader;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static java.util.function.Function.identity;

/**
 * A provider of pipeline parsers.
 */

public final class CSConfigurationParsers
  implements CSConfigurationParsersType
{
  private final JcaPEMKeyConverter keyConverter;
  private final Map<String, CSCertificateOutputProviderType> outputProviders;
  private final CSStrings strings;
  private final Map<String, CSDNSConfiguratorProviderType> dnsProviders;

  /**
   * A provider of pipeline parsers.
   *
   * @param inKeyConverter    A PEM key converter
   * @param inOutputProviders The supported output providers
   * @param inDNSProviders    The supported DNS providers
   * @param inStrings         The string resources
   */

  public CSConfigurationParsers(
    final JcaPEMKeyConverter inKeyConverter,
    final Map<String, CSCertificateOutputProviderType> inOutputProviders,
    final Map<String, CSDNSConfiguratorProviderType> inDNSProviders,
    final CSStrings inStrings)
  {
    this.keyConverter =
      Objects.requireNonNull(inKeyConverter, "keyConverter");
    this.outputProviders =
      Objects.requireNonNull(inOutputProviders, "outputProviders");
    this.dnsProviders =
      Objects.requireNonNull(inDNSProviders, "dnsProviders");
    this.strings =
      Objects.requireNonNull(inStrings, "strings");
  }

  /**
   * A provider of pipeline parsers.
   *
   * @param locale The locale for string resources
   *
   * @throws IOException On I/O errors
   */

  public CSConfigurationParsers(
    final Locale locale)
    throws IOException
  {
    this(
      new JcaPEMKeyConverter(),
      loadNamedProviders(CSCertificateOutputProviderType.class),
      loadNamedProviders(CSDNSConfiguratorProviderType.class),
      new CSStrings(locale)
    );
  }

  /**
   * A provider of pipeline parsers.
   *
   * @throws IOException On I/O errors
   */

  public CSConfigurationParsers()
    throws IOException
  {
    this(Locale.getDefault());
  }

  private static <T extends CSNamedProviderType> Map<String, T> loadNamedProviders(
    final Class<T> clazz)
  {
    return Map.copyOf(
      ServiceLoader.load(clazz)
        .stream()
        .map(ServiceLoader.Provider::get)
        .collect(Collectors.toMap(CSNamedProviderType::name, identity()))
    );
  }

  @Override
  public CSConfigurationParserType createParserWithContext(
    final Path baseDirectory,
    final URI source,
    final InputStream stream,
    final Consumer<ParseStatus> statusConsumer)
  {
    Objects.requireNonNull(baseDirectory, "baseDirectory");
    Objects.requireNonNull(source, "source");
    Objects.requireNonNull(stream, "stream");
    Objects.requireNonNull(statusConsumer, "statusConsumer");

    return new CSConfigurationParser(
      this.strings,
      this.keyConverter,
      this.outputProviders,
      this.dnsProviders,
      baseDirectory,
      stream,
      source,
      statusConsumer
    );
  }
}
