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


import com.io7m.anethum.api.ParseStatus;
import com.io7m.jxtrand.vanilla.JXTAbstractStrings;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * An abstract provider implementation.
 */

public abstract class CSAbstractNamedProvider implements CSNamedProviderType
{
  private final CSNamedProviderStrings strings;

  /**
   * An abstract provider implementation.
   *
   * @param inStrings String resources
   */

  private CSAbstractNamedProvider(
    final CSNamedProviderStrings inStrings)
  {
    this.strings =
      Objects.requireNonNull(inStrings, "strings");
  }

  /**
   * An abstract provider implementation.
   *
   * @param locale A locale for error messages
   *
   * @throws IOException On I/O errors
   */

  protected CSAbstractNamedProvider(
    final Locale locale)
    throws IOException
  {
    this(new CSNamedProviderStrings(locale));
  }

  protected final void checkParameters(
    final CSConfigurationParameters parameters)
    throws CSConfigurationException
  {
    Objects.requireNonNull(parameters, "parameters");

    final var errors =
      new ArrayList<ParseStatus>();

    final var definitions =
      this.parameters();
    final var parameterMap =
      parameters.parameters();

    final var requiredParameters =
      definitions.values()
        .stream()
        .filter(CSConfigurationParameterDescription::required)
        .toList();

    final var requiredParameterNames =
      definitions.values()
        .stream()
        .filter(CSConfigurationParameterDescription::required)
        .map(CSConfigurationParameterDescription::name)
        .toList();

    final var recognizedParameterNames =
      definitions.values()
        .stream()
        .map(CSConfigurationParameterDescription::name)
        .collect(Collectors.toSet());

    this.checkRequiredParameters(
      parameters,
      errors,
      parameterMap,
      requiredParameters
    );

    this.checkRecognizedParameters(
      parameters,
      errors,
      parameterMap,
      recognizedParameterNames
    );

    if (!errors.isEmpty()) {
      throw new CSConfigurationException(
        errors, this.strings.format("errorProviderConfiguration")
      );
    }
  }

  private void checkRecognizedParameters(
    final CSConfigurationParameters parameters,
    final Collection<ParseStatus> errors,
    final Map<String, String> parameterMap,
    final Collection<String> recognizedParameterNames)
  {
    final var builder =
      ParseStatus.builder(
          "error-parameter-unrecognized",
          this.strings.format("errorUnrecognizedParameter"))
        .withLexical(parameters.lexical());

    var failed = false;
    var unrecognizedIndex = 0;

    for (final var specified : parameterMap.keySet()) {
      if (!recognizedParameterNames.contains(specified)) {
        failed = true;
        builder.withAttribute(
          "Unrecognized (%d)".formatted(Integer.valueOf(unrecognizedIndex)),
          specified
        );
        ++unrecognizedIndex;
      }
    }

    if (failed) {
      errors.add(builder.build());
    }
  }

  private void checkRequiredParameters(
    final CSConfigurationParameters parameters,
    final Collection<ParseStatus> errors,
    final Map<String, String> parameterMap,
    final Iterable<CSConfigurationParameterDescription> requiredParameters)
  {
    final var builder =
      ParseStatus.builder(
          "error-parameter-required",
          this.strings.format("errorMissingRequiredParameter"))
        .withLexical(parameters.lexical());

    var failed = false;
    var missingIndex = 0;
    for (final var required : requiredParameters) {
      if (!parameterMap.containsKey(required.name())) {
        failed = true;
        builder.withAttribute(
          "Missing (%d)".formatted(Integer.valueOf(missingIndex)),
          required.name()
        );
        ++missingIndex;
      }
    }

    if (failed) {
      errors.add(builder.build());
    }
  }

  private static final class CSNamedProviderStrings extends JXTAbstractStrings
  {
    /**
     * String resources.
     *
     * @param locale The locale
     *
     * @throws IOException On I/O errors
     */

    CSNamedProviderStrings(
      final Locale locale)
      throws IOException
    {
      super(
        locale,
        CSNamedProviderStrings.class,
        "/com/io7m/certusine/api/internal",
        "Messages"
      );
    }

    @Override
    public String format(
      final String id,
      final Object... args)
    {
      return super.format(id, args).trim();
    }

    @Override
    public String toString()
    {
      return String.format(
        "[CSNamedProviderStrings 0x%08x]",
        Integer.valueOf(this.hashCode())
      );
    }
  }
}
