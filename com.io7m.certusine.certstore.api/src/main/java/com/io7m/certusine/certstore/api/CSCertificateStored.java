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

package com.io7m.certusine.certstore.api;

import com.io7m.certusine.api.CSCertificateName;

import java.io.Serializable;
import java.time.OffsetDateTime;
import java.util.Objects;

/**
 * A stored certificate.
 *
 * @param domain                         The domain name
 * @param name                           The certificate name
 * @param createdOn                      The time/date this certificate was
 *                                       created
 * @param expiresOn                      The time/date this certificate expires
 * @param pemEncodedCertificate          The single PEM-encoded certificate
 * @param pemEncodedCertificateFullChain The full PEM-encoded certificate chain
 */

public record CSCertificateStored(
  String domain,
  CSCertificateName name,
  OffsetDateTime createdOn,
  OffsetDateTime expiresOn,
  String pemEncodedCertificate,
  String pemEncodedCertificateFullChain)
  implements Serializable
{
  /**
   * A stored certificate.
   *
   * @param domain                         The domain name
   * @param name                           The certificate name
   * @param createdOn                      The time/date this certificate was
   *                                       created
   * @param expiresOn                      The time/date this certificate
   *                                       expires
   * @param pemEncodedCertificate          The single PEM-encoded certificate
   * @param pemEncodedCertificateFullChain The full PEM-encoded certificate
   *                                       chain
   */

  public CSCertificateStored
  {
    Objects.requireNonNull(
      domain, "domain");
    Objects.requireNonNull(
      name, "name");
    Objects.requireNonNull(
      createdOn, "createdOn");
    Objects.requireNonNull(
      expiresOn, "expiresOn");
    Objects.requireNonNull(
      pemEncodedCertificate, "pemEncodedCertificate");
    Objects.requireNonNull(
      pemEncodedCertificateFullChain, "pemEncodedCertificateFullChain");
  }

  /**
   * @return The certificate identifier
   */

  public String identifier()
  {
    return "%s/%s".formatted(this.domain, this.name.value());
  }
}
