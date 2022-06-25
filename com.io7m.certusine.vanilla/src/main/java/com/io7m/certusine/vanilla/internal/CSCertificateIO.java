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

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.IOException;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;

/**
 * Functions to encode and decode certificates.
 */

public final class CSCertificateIO
{
  private CSCertificateIO()
  {

  }

  /**
   * Encode a chain of X509 certificates as a PEM-encoded string.
   *
   * @param certificateChain The certificates
   *
   * @return A PEM string
   *
   * @throws IOException On errors
   */

  public static String encodeCertificates(
    final List<X509Certificate> certificateChain)
    throws IOException
  {
    Objects.requireNonNull(certificateChain, "certificateChain");

    final var writer = new StringWriter();
    try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
      for (final var certificate : certificateChain) {
        pemWriter.writeObject(certificate);
      }
      pemWriter.flush();
    }
    return writer.toString();
  }

  /**
   * Encode a chain of X509 certificates as a PEM-encoded string.
   *
   * @param certificate The certificate
   *
   * @return A PEM string
   *
   * @throws IOException On errors
   */

  public static String encodeCertificate(
    final X509Certificate certificate)
    throws IOException
  {
    Objects.requireNonNull(certificate, "certificate");

    final var writer = new StringWriter();
    try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
      pemWriter.writeObject(certificate);
      pemWriter.flush();
    }
    return writer.toString();
  }

  /**
   * Encode public key as a PEM-encoded string.
   *
   * @param key The key
   *
   * @return A PEM string
   *
   * @throws IOException On errors
   */

  public static String encodePublicKey(
    final PublicKey key)
    throws IOException
  {
    Objects.requireNonNull(key, "key");

    final var writer = new StringWriter();
    try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
      pemWriter.writeObject(key);
      pemWriter.flush();
    }
    return writer.toString();
  }

  /**
   * Encode private key as a PEM-encoded string.
   *
   * @param key The key
   *
   * @return A PEM string
   *
   * @throws IOException On errors
   */

  public static String encodePrivateKey(
    final PrivateKey key)
    throws IOException
  {
    Objects.requireNonNull(key, "key");

    final var writer = new StringWriter();
    try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
      pemWriter.writeObject(key);
      pemWriter.flush();
    }
    return writer.toString();
  }
}
