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

import com.io7m.certusine.api.CSCertificateName;
import com.io7m.jdeferthrow.core.ExceptionTracker;
import com.io7m.looseleaf.protocol.v1.LLv1Error;
import com.io7m.looseleaf.protocol.v1.LLv1Errors;
import com.io7m.looseleaf.protocol.v1.LLv1Messages;
import com.io7m.looseleaf.protocol.v1.LLv1RUD;
import com.io7m.looseleaf.protocol.v1.LLv1Result;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import static java.net.http.HttpRequest.BodyPublishers.ofByteArray;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.file.StandardCopyOption.ATOMIC_MOVE;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.TRUNCATE_EXISTING;

/**
 * A downloader that can take certificates from a looseleaf database and save it
 * to a local directory.
 */

public final class CSLLDownloader
{
  private final LLv1Messages messages;
  private final Path directory;
  private final HttpClient client;
  private final String domain;
  private final CSCertificateName certificateName;
  private final HttpRequest request;
  private final String namePub;
  private final String namePri;
  private final String nameCert;
  private final String nameCertFullChain;

  /**
   * @return The certificate name
   */

  public CSCertificateName certificateName()
  {
    return this.certificateName;
  }

  private CSLLDownloader(
    final LLv1Messages inMessages,
    final Path inDirectory,
    final HttpClient inClient,
    final String inDomain,
    final CSCertificateName inCertificateName,
    final HttpRequest inRequest,
    final String inNamePub,
    final String inNamePri,
    final String inNameCert,
    final String inNameCertFullChain)
  {
    this.messages =
      Objects.requireNonNull(inMessages, "messages");
    this.directory =
      Objects.requireNonNull(inDirectory, "directory");
    this.client =
      Objects.requireNonNull(inClient, "client");
    this.domain =
      Objects.requireNonNull(inDomain, "domain");
    this.certificateName =
      Objects.requireNonNull(inCertificateName, "certificateName");
    this.request =
      Objects.requireNonNull(inRequest, "request");
    this.namePub =
      Objects.requireNonNull(inNamePub, "namePub");
    this.namePri =
      Objects.requireNonNull(inNamePri, "namePri");
    this.nameCert =
      Objects.requireNonNull(inNameCert, "nameCert");
    this.nameCertFullChain =
      Objects.requireNonNull(inNameCertFullChain, "nameCertFullChain");
  }

  private static String base64(
    final String formatted)
  {
    return Base64.getUrlEncoder().encodeToString(formatted.getBytes(UTF_8));
  }

  /**
   * Create a new downloader.
   *
   * @param directory       The output directory
   * @param baseURI         The base URI for the API
   * @param credentials     The credentials
   * @param domain          The domain
   * @param certificateName The certificate name
   *
   * @return A new downloader
   */

  public static CSLLDownloader create(
    final Path directory,
    final String baseURI,
    final CSLLCredentials credentials,
    final String domain,
    final CSCertificateName certificateName)
  {
    return create(
      new LLv1Messages(),
      HttpClient.newHttpClient(),
      directory,
      baseURI,
      credentials,
      domain,
      certificateName
    );
  }

  /**
   * Create a new downloader.
   *
   * @param messages        The V1 message deserializer
   * @param client          The client
   * @param directory       The output directory
   * @param baseURI         The base URI for the API
   * @param credentials     The credentials
   * @param domain          The domain
   * @param certificateName The certificate name
   *
   * @return A new downloader
   */

  public static CSLLDownloader create(
    final LLv1Messages messages,
    final HttpClient client,
    final Path directory,
    final String baseURI,
    final CSLLCredentials credentials,
    final String domain,
    final CSCertificateName certificateName)
  {
    Objects.requireNonNull(messages, "messages");
    Objects.requireNonNull(client, "client");
    Objects.requireNonNull(directory, "inDirectory");
    Objects.requireNonNull(baseURI, "inBaseURI");
    Objects.requireNonNull(credentials, "inCredentials");
    Objects.requireNonNull(domain, "inDomain");
    Objects.requireNonNull(certificateName, "inCertificateName");

    final var namePub =
      "/certificates/%s/%s/public_key"
        .formatted(
          domain,
          certificateName.value());

    final var namePri =
      "/certificates/%s/%s/private_key"
        .formatted(
          domain,
          certificateName.value());

    final var nameCert =
      "/certificates/%s/%s/certificate"
        .formatted(
          domain,
          certificateName.value());

    final var nameCertFullChain =
      "/certificates/%s/%s/certificate_full_chain"
        .formatted(
          domain,
          certificateName.value());

    final var rud =
      new LLv1RUD(
        Set.of(
          namePub,
          namePri,
          nameCert,
          nameCertFullChain
        ),
        Map.of(),
        Set.of()
      );

    try {
      final var formattedCredentials =
        base64("%s:%s".formatted(credentials.user(), credentials.password()));
      final var authorization =
        "Basic " + formattedCredentials;
      final var endpointURI =
        "%s/v1/rud".formatted(baseURI.replaceAll("/+$", ""));

      final var request =
        HttpRequest.newBuilder()
          .POST(ofByteArray(messages.serialize(rud)))
          .header("Authorization", authorization)
          .uri(URI.create(endpointURI))
          .build();

      return new CSLLDownloader(
        messages,
        directory,
        client,
        domain,
        certificateName,
        request,
        namePub,
        namePri,
        nameCert,
        nameCertFullChain
      );
    } catch (final IOException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Execute the downloader once. May be called multiple times.
   *
   * @throws IOException          On I/O errors
   * @throws InterruptedException On interruptions
   */

  public void execute()
    throws IOException, InterruptedException
  {
    final var response =
      this.client.send(this.request, BodyHandlers.ofByteArray());
    final var message =
      this.messages.deserialize(response.body());

    if (message instanceof LLv1Errors errors) {
      final var text = new StringBuilder();
      final var lineSeparator = System.lineSeparator();
      text.append("Server returned one or more errors.");
      text.append(lineSeparator);
      text.append("  HTTP status: ");
      text.append(response.statusCode());
      text.append(lineSeparator);

      for (final var error : errors.errors()) {
        errorAppend(text, lineSeparator, error);
      }

      throw new IOException(text.toString());
    }

    if (message instanceof LLv1Error error) {
      final var text = new StringBuilder();
      final var lineSeparator = System.lineSeparator();
      text.append("Server returned one or more errors.");
      text.append(lineSeparator);
      text.append("  HTTP status: ");
      text.append(response.statusCode());
      text.append(lineSeparator);
      errorAppend(text, lineSeparator, error);
      throw new IOException(text.toString());
    }

    if (message instanceof LLv1Result result) {
      this.executeResult(result);
      return;
    }

    throw new IOException("Received unexpected result: %s".formatted(message));
  }

  private static void errorAppend(
    final StringBuilder text,
    final String lineSeparator,
    final LLv1Error error)
  {
    text.append("  ");
    text.append(error.errorCode());
    text.append(": ");
    text.append(error.message());
    text.append(lineSeparator);
  }

  private void executeResult(
    final LLv1Result result)
    throws IOException
  {
    final var exceptions =
      new ExceptionTracker<IOException>();
    final var map =
      result.values();

    try {
      this.save(map, this.namePub, "public_key");
    } catch (final IOException e) {
      exceptions.addException(e);
    }

    try {
      this.save(map, this.namePri, "private_key");
    } catch (final IOException e) {
      exceptions.addException(e);
    }

    try {
      this.save(map, this.nameCert, "certificate");
    } catch (final IOException e) {
      exceptions.addException(e);
    }

    try {
      this.save(map, this.nameCertFullChain, "certificate_full_chain");
    } catch (final IOException e) {
      exceptions.addException(e);
    }

    exceptions.throwIfNecessary();
  }

  private void save(
    final Map<String, String> values,
    final String keyName,
    final String fileName)
    throws IOException
  {
    final var value = values.get(keyName);
    if (value == null) {
      throw new IOException(
        "Returned keys do not contain \"%s\"".formatted(keyName)
      );
    }

    final var certificates =
      this.directory.resolve("certificates");
    final var byDomain =
      certificates.resolve(this.domain);
    final var byName =
      byDomain.resolve(this.certificateName.value());
    final var file =
      byName.resolve(fileName);
    final var fileTmp =
      byName.resolve(fileName + ".tmp");

    Files.createDirectories(byName);

    try (var output =
           Files.newOutputStream(fileTmp, CREATE, TRUNCATE_EXISTING)) {
      output.write(value.getBytes(UTF_8));
      output.flush();
      Files.move(fileTmp, file, REPLACE_EXISTING, ATOMIC_MOVE);
    }
  }
}
