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

package com.io7m.certusine.looseleaf.internal;

import com.io7m.certusine.api.CSCertificateOutputData;
import com.io7m.certusine.api.CSCertificateOutputType;
import com.io7m.certusine.looseleaf.CSLLCredentials;
import com.io7m.looseleaf.protocol.v1.LLv1Errors;
import com.io7m.looseleaf.protocol.v1.LLv1Messages;
import com.io7m.looseleaf.protocol.v1.LLv1RUD;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

import static java.net.http.HttpRequest.BodyPublishers.ofByteArray;
import static java.net.http.HttpResponse.BodyHandlers.ofByteArray;
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * A looseleaf certificate output.
 */

public final class CSLLOutput
  implements CSCertificateOutputType
{
  private static final Logger LOG =
    LoggerFactory.getLogger(CSLLOutput.class);
  private static final Pattern END_SLASHES =
    Pattern.compile("/+$");

  private final CSLLStrings strings;
  private final CSLLCredentials credentials;
  private final String name;
  private final String endpoint;
  private final HttpClient client;
  private final LLv1Messages messages;

  /**
   * A looseleaf certificate output.
   *
   * @param inStrings     The strings
   * @param inCredentials The credentials
   * @param inName        The output name
   * @param inEndpoint    The endpoint base address
   */

  public CSLLOutput(
    final CSLLStrings inStrings,
    final String inName,
    final CSLLCredentials inCredentials,
    final String inEndpoint)
  {
    this.strings =
      Objects.requireNonNull(inStrings, "inStrings");
    this.credentials =
      Objects.requireNonNull(inCredentials, "inCredentials");
    this.name =
      Objects.requireNonNull(inName, "name");
    this.endpoint =
      END_SLASHES.matcher(
          Objects.requireNonNull(inEndpoint, "inEndpoint"))
        .replaceAll("");

    this.client =
      HttpClient.newHttpClient();
    this.messages =
      new LLv1Messages();
  }

  @Override
  public String type()
  {
    return "looseleaf";
  }

  @Override
  public String name()
  {
    return this.name;
  }

  @Override
  public void write(
    final CSCertificateOutputData outputData)
    throws IOException, InterruptedException
  {
    Objects.requireNonNull(outputData, "outputData");
    this.sendData(outputData);
  }

  private void sendData(
    final CSCertificateOutputData outputData)
    throws IOException, InterruptedException
  {
    final var endpointURI =
      "%s/v1/rud".formatted(this.endpoint);

    LOG.debug("rud endpoint: {}", endpointURI);

    final var namePub =
      "/certificates/%s/%s/public_key"
        .formatted(
          outputData.domainName(),
          outputData.name()
            .value());

    final var namePri =
      "/certificates/%s/%s/private_key"
        .formatted(
          outputData.domainName(),
          outputData.name()
            .value());

    final var nameCert =
      "/certificates/%s/%s/certificate"
        .formatted(
          outputData.domainName(),
          outputData.name()
            .value());

    final var nameCertFullChain =
      "/certificates/%s/%s/certificate_full_chain"
        .formatted(
          outputData.domainName(),
          outputData.name()
            .value());

    final var rud =
      new LLv1RUD(
        Set.of(),
        Map.ofEntries(
          Map.entry(namePub, outputData.pemEncodedPublicKey()),
          Map.entry(namePri, outputData.pemEncodedPrivateKey()),
          Map.entry(nameCert, outputData.pemEncodedCertificate()),
          Map.entry(nameCertFullChain, outputData.pemEncodedFullChain())
        ),
        Set.of()
      );

    final var authorization =
      "Basic " + base64("%s:%s".formatted(
        this.credentials.user(),
        this.credentials.password()));

    final var request =
      HttpRequest.newBuilder()
        .POST(ofByteArray(this.messages.serialize(rud)))
        .header("Authorization", authorization)
        .uri(URI.create(endpointURI))
        .build();

    final var httpResponse =
      this.client.send(request, ofByteArray());

    final var response =
      this.messages.deserialize(httpResponse.body());

    if (httpResponse.statusCode() >= 400) {
      if (response instanceof LLv1Errors errors) {
        for (final var error : errors.errors()) {
          LOG.error("{}: {}", error.errorCode(), error.message());
        }
      }
      throw new IOException(
        this.strings.format(
          "errorServer",
          Integer.valueOf(httpResponse.statusCode()))
      );
    }
  }

  private static String base64(
    final String formatted)
  {
    return Base64.getUrlEncoder().encodeToString(formatted.getBytes(UTF_8));
  }
}
