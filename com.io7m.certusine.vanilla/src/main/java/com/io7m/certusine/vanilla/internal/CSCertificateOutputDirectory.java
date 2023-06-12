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

package com.io7m.certusine.vanilla.internal;

import com.io7m.certusine.api.CSCertificateOutputData;
import com.io7m.certusine.api.CSCertificateOutputType;
import com.io7m.certusine.api.CSTelemetryServiceType;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.util.Objects;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.file.StandardCopyOption.ATOMIC_MOVE;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.TRUNCATE_EXISTING;

/**
 * A directory-based certificate output.
 */

public final class CSCertificateOutputDirectory
  implements CSCertificateOutputType
{
  private final Path path;
  private final String name;

  /**
   * A directory-based certificate output.
   *
   * @param inName The output name
   * @param inPath The output directory path
   */

  public CSCertificateOutputDirectory(
    final String inName,
    final Path inPath)
  {
    this.name =
      Objects.requireNonNull(inName, "inName");
    this.path =
      Objects.requireNonNull(inPath, "path");
  }

  @Override
  public String toString()
  {
    return "[CSCertificateOutputDirectory 0x%s]"
      .formatted(Long.toUnsignedString(this.hashCode(), 16));
  }

  @Override
  public String type()
  {
    return "directory";
  }

  @Override
  public String name()
  {
    return this.name;
  }

  @Override
  public void write(
    final CSTelemetryServiceType telemetry,
    final CSCertificateOutputData outputData)
    throws IOException
  {
    Objects.requireNonNull(telemetry, "telemetry");
    Objects.requireNonNull(outputData, "outputData");

    final var span =
      telemetry.tracer()
        .spanBuilder("WriteDirectory")
        .setAttribute("certusine.target", this.path.toString())
        .startSpan();

    try (var ignored = span.makeCurrent()) {
      this.writeData(outputData);
    } catch (final Exception e) {
      CSTelemetryServiceType.recordExceptionAndSetError(e);
      throw e;
    } finally {
      span.end();
    }
  }

  private void writeData(
    final CSCertificateOutputData outputData)
    throws IOException
  {
    final var byDomain =
      this.path.resolve(URLEncoder.encode(outputData.domainName(), UTF_8));
    final var byName =
      byDomain.resolve(outputData.name().value());

    Files.createDirectories(byName);

    final var pubKey =
      byName.resolve("public.key");
    final var pubKeyTmp =
      byName.resolve("public.key.tmp");

    final var privKey =
      byName.resolve("private.key");
    final var privKeyTmp =
      byName.resolve("private.key.tmp");

    final var cert =
      byName.resolve("certificate.pem");
    final var certTmp =
      byName.resolve("certificate.pem.tmp");

    final var fullChain =
      byName.resolve("full_chain.pem");
    final var fullChainTmp =
      byName.resolve("full_chain.pem.tmp");

    final var openOptions =
      new OpenOption[]{TRUNCATE_EXISTING, CREATE};

    try (var output =
           Files.newBufferedWriter(pubKeyTmp, UTF_8, openOptions)) {
      output.write(outputData.pemEncodedPublicKey());
      output.newLine();
      output.flush();
      Files.move(pubKeyTmp, pubKey, ATOMIC_MOVE, REPLACE_EXISTING);
    }

    try (var output =
           Files.newBufferedWriter(privKeyTmp, UTF_8, openOptions)) {
      output.write(outputData.pemEncodedPrivateKey());
      output.newLine();
      output.flush();
      Files.move(privKeyTmp, privKey, ATOMIC_MOVE, REPLACE_EXISTING);
    }

    try (var output =
           Files.newBufferedWriter(certTmp, UTF_8, openOptions)) {
      output.write(outputData.pemEncodedCertificate());
      output.newLine();
      output.flush();
      Files.move(certTmp, cert, ATOMIC_MOVE, REPLACE_EXISTING);
    }

    try (var output =
           Files.newBufferedWriter(fullChainTmp, UTF_8, openOptions)) {
      output.write(outputData.pemEncodedFullChain());
      output.newLine();
      output.flush();
      Files.move(fullChainTmp, fullChain, ATOMIC_MOVE, REPLACE_EXISTING);
    }
  }
}
