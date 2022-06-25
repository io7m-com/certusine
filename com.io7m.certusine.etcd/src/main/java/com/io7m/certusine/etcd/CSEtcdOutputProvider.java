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


package com.io7m.certusine.etcd;

import com.io7m.anethum.common.ParseSeverity;
import com.io7m.anethum.common.ParseStatus;
import com.io7m.certusine.api.CSCertificateOutputProviderType;
import com.io7m.certusine.api.CSCertificateOutputType;
import com.io7m.certusine.api.CSConfigurationException;
import com.io7m.certusine.api.CSConfigurationParameters;
import com.io7m.certusine.etcd.internal.CSEtcdCredentials;
import com.io7m.certusine.etcd.internal.CSEtcdOutput;
import com.io7m.certusine.etcd.internal.CSEtcdStrings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * An etcd certificate output.
 */

public final class CSEtcdOutputProvider
  implements CSCertificateOutputProviderType
{
  private static final Logger LOG =
    LoggerFactory.getLogger(CSEtcdOutputProvider.class);

  private static final String ENDPOINT_PARAMETER = "endpoint";
  private static final String USERNAME_PARAMETER = "username";
  private static final String PASSWORD_PARAMETER = "password";

  private static final List<String> REQUIRED_PARAMETERS =
    List.of(ENDPOINT_PARAMETER);

  private static final Set<String> KNOWN_PARAMETERS =
    Set.of(ENDPOINT_PARAMETER, USERNAME_PARAMETER, PASSWORD_PARAMETER);

  private final CSEtcdStrings strings;

  /**
   * Access to etcd.
   *
   * @param inStrings String resources
   */

  public CSEtcdOutputProvider(
    final CSEtcdStrings inStrings)
  {
    this.strings = Objects.requireNonNull(inStrings, "strings");
  }

  /**
   * Access to etcd.
   *
   * @param locale A locale for error messages
   *
   * @throws IOException On I/O errors
   */

  public CSEtcdOutputProvider(
    final Locale locale)
    throws IOException
  {
    this(new CSEtcdStrings(locale));
  }

  /**
   * Access to etcd.
   *
   * @throws IOException On I/O errors
   */

  public CSEtcdOutputProvider()
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

    Optional<CSEtcdCredentials> credentials = Optional.empty();
    if (parameterMap.containsKey(USERNAME_PARAMETER)) {
      if (parameterMap.containsKey(PASSWORD_PARAMETER)) {
        credentials = Optional.of(
          new CSEtcdCredentials(
            parameterMap.get(USERNAME_PARAMETER),
            parameterMap.get(PASSWORD_PARAMETER)
          )
        );
      }
    }

    if (errors.isEmpty()) {
      return new CSEtcdOutput(
        this.strings,
        name,
        credentials,
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
    return "etcd";
  }
}
