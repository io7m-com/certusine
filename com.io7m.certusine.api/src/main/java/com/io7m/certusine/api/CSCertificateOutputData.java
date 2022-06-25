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

import java.util.Objects;

/**
 * The data passed to a certificate output.
 *
 * @param domainName            The domain
 * @param name                  The certificate name
 * @param pemEncodedPublicKey   The PEM-encoded public key
 * @param pemEncodedPrivateKey  The PEM-encoded private key
 * @param pemEncodedCertificate The PEM-encoded certificate
 * @param pemEncodedFullChain   The PEM-encoded full certificate chain
 */

public record CSCertificateOutputData(
  String domainName,
  CSCertificateName name,
  String pemEncodedPublicKey,
  String pemEncodedPrivateKey,
  String pemEncodedCertificate,
  String pemEncodedFullChain)
{
  /**
   * The data passed to a certificate output.
   *
   * @param domainName            The domain
   * @param name                  The certificate name
   * @param pemEncodedPublicKey   The PEM-encoded public key
   * @param pemEncodedPrivateKey  The PEM-encoded private key
   * @param pemEncodedCertificate The PEM-encoded certificate
   * @param pemEncodedFullChain   The PEM-encoded full certificate chain
   */

  public CSCertificateOutputData
  {
    Objects.requireNonNull(domainName, "domainName");
    Objects.requireNonNull(name, "name");
    Objects.requireNonNull(pemEncodedPublicKey, "pemEncodedPublicKey");
    Objects.requireNonNull(pemEncodedPrivateKey, "pemEncodedPrivateKey");
    Objects.requireNonNull(pemEncodedCertificate, "pemEncodedCertificate");
    Objects.requireNonNull(pemEncodedFullChain, "pemEncodedFullChain");
  }
}
