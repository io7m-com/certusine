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

import java.io.Closeable;
import java.io.IOException;
import java.util.Optional;

/**
 * A certificate store.
 */

public interface CSCertificateStoreType
  extends Closeable
{
  /**
   * @return {@code true} if the store has been closed
   */

  boolean isClosed();

  /**
   * Create or update a certificate.
   *
   * @param certificate The certificate
   *
   * @throws IOException On I/O errors
   */

  void put(CSCertificateStored certificate)
    throws IOException;

  /**
   * Find a certificate that has the given domain and name.
   *
   * @param domain The domain
   * @param name   The certificate name
   *
   * @return The certificate, if one exists
   *
   * @throws IOException On errors
   */

  Optional<CSCertificateStored> find(
    String domain,
    CSCertificateName name)
    throws IOException;

  /**
   * Delete the certificate with the given domain and name.
   *
   * @param domain The domain
   * @param name   The certificate name
   *
   * @return {@code true} if a certificate existed and was deleted
   *
   * @throws IOException On I/O errors
   */

  boolean delete(
    String domain,
    CSCertificateName name)
    throws IOException;
}
