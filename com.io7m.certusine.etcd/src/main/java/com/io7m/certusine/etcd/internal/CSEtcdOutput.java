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

package com.io7m.certusine.etcd.internal;

import com.io7m.certusine.api.CSCertificateOutputData;
import com.io7m.certusine.api.CSCertificateOutputType;
import com.io7m.certusine.etcd.internal.dto.CSEMessageType.CSEAuthenticateResponse;
import com.io7m.certusine.etcd.internal.dto.CSEMessageType.CSEError;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

import static com.io7m.certusine.etcd.internal.dto.CSEMessageType.CEKV;
import static com.io7m.certusine.etcd.internal.dto.CSEMessageType.CERequestPut;
import static com.io7m.certusine.etcd.internal.dto.CSEMessageType.CSEAuthenticate;
import static com.io7m.certusine.etcd.internal.dto.CSEMessageType.CSETransaction;
import static java.net.http.HttpRequest.BodyPublishers.ofByteArray;
import static java.net.http.HttpResponse.BodyHandlers.ofByteArray;
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * An etcd certificate output.
 */

public final class CSEtcdOutput
  implements CSCertificateOutputType
{
  private static final Logger LOG =
    LoggerFactory.getLogger(CSEtcdOutput.class);
  private static final Pattern END_SLASHES =
    Pattern.compile("/+$");
  private final CSEtcdStrings strings;
  private final Optional<CSEtcdCredentials> credentials;
  private final String name;
  private final String endpoint;
  private final HttpClient client;
  private final CSEtcdMessages messages;
  private Optional<String> token;

  /**
   * An etcd certificate output.
   *
   * @param inStrings     The strings
   * @param inCredentials The credentials
   * @param inName        The output name
   * @param inEndpoint    The endpoint base address
   */

  public CSEtcdOutput(
    final CSEtcdStrings inStrings,
    final String inName,
    final Optional<CSEtcdCredentials> inCredentials,
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
      new CSEtcdMessages();
    this.token =
      Optional.empty();
  }

  @Override
  public String type()
  {
    return "etcd";
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

    if (this.credentials.isPresent()) {
      this.authenticate(this.credentials.get());
    }

    this.sendData(outputData);
  }

  private void sendData(
    final CSCertificateOutputData outputData)
    throws IOException, InterruptedException
  {
    final var txnTarget =
      "%s/v3/kv/txn".formatted(this.endpoint);

    LOG.debug("transaction endpoint: {}", txnTarget);

    final var base64 =
      Base64.getUrlEncoder();

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

    final var pubKV = new CEKV(
      base64.encodeToString(namePub.getBytes(UTF_8)),
      base64.encodeToString(outputData.pemEncodedPublicKey().getBytes(UTF_8))
    );

    final var priKV = new CEKV(
      base64.encodeToString(namePri.getBytes(UTF_8)),
      base64.encodeToString(outputData.pemEncodedPrivateKey().getBytes(UTF_8))
    );

    final var certKV = new CEKV(
      base64.encodeToString(nameCert.getBytes(UTF_8)),
      base64.encodeToString(outputData.pemEncodedCertificate().getBytes(UTF_8))
    );

    final var certChainKV = new CEKV(
      base64.encodeToString(nameCertFullChain.getBytes(UTF_8)),
      base64.encodeToString(outputData.pemEncodedFullChain().getBytes(UTF_8))
    );

    final var txn =
      new CSETransaction(
        List.of(),
        List.of(
          new CERequestPut(pubKV),
          new CERequestPut(priKV),
          new CERequestPut(certKV),
          new CERequestPut(certChainKV)
        )
      );

    final var builder =
      HttpRequest.newBuilder()
        .POST(ofByteArray(this.messages.serialize(txn)))
        .uri(URI.create(txnTarget));

    this.token.ifPresent(t -> builder.header("Authorization", t));

    final var request =
      builder.build();

    final var httpResponse =
      this.client.send(request, ofByteArray());
    final var data =
      httpResponse.body();
    final var message =
      this.messages.deserialize(data);
  }

  private void authenticate(
    final CSEtcdCredentials creds)
    throws IOException, InterruptedException
  {
    final var authTarget =
      "%s/v3/auth/authenticate".formatted(this.endpoint);

    LOG.debug("authentication endpoint: {}", authTarget);

    final var authMessage =
      new CSEAuthenticate(creds.user(), creds.password());
    final var request =
      HttpRequest.newBuilder()
        .POST(ofByteArray(this.messages.serialize(authMessage)))
        .uri(URI.create(authTarget))
        .build();

    final var httpResponse =
      this.client.send(request, ofByteArray());
    final var data =
      httpResponse.body();
    final var message =
      this.messages.deserialize(data);

    if (message instanceof CSEAuthenticateResponse authResponse) {
      this.token = Optional.of(authResponse.token());
    } else if (message instanceof CSEError error) {
      throw new IOException(error.message());
    } else {
      throw new IOException(
        this.strings.format("errorUnexpectedResponse", message)
      );
    }
  }
}
