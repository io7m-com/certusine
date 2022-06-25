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

package com.io7m.certusine.tests;

import com.io7m.certusine.api.CSCertificateName;
import com.io7m.certusine.certstore.api.CSCertificateStoreType;
import com.io7m.certusine.certstore.api.CSCertificateStored;

import java.util.HashMap;
import java.util.Optional;

public final class CSFakeCertificateStore
  implements CSCertificateStoreType
{
  public final HashMap<String, CSCertificateStored> certificates;

  public CSFakeCertificateStore()
  {
    this.certificates = new HashMap<String, CSCertificateStored>();
  }

  @Override
  public boolean isClosed()
  {
    return false;
  }

  @Override
  public void put(
    final CSCertificateStored certificate)
  {
    this.certificates.put(certificate.identifier(), certificate);
  }

  @Override
  public Optional<CSCertificateStored> find(
    final String domain,
    final CSCertificateName name)
  {
    final var id = "%s/%s".formatted(domain, name.value());
    return Optional.ofNullable(this.certificates.get(id));
  }

  @Override
  public boolean delete(
    final String domain,
    final CSCertificateName name)
  {
    final var id = "%s/%s".formatted(domain, name.value());
    return this.certificates.remove(id) != null;
  }

  @Override
  public void close()
  {

  }
}
