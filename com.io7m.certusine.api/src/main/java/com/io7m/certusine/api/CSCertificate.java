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

import java.security.KeyPair;
import java.util.List;
import java.util.Objects;

/**
 * A request for a certificate within a domain. A certificate is used to assign
 * some degree of trust as to the identity of the holder of the keypair.
 *
 * @param name    The name used to refer to certificate
 * @param keyPair The keypair used for the certificate
 * @param hosts   The list of hosts in the certificate
 */

public record CSCertificate(
  CSCertificateName name,
  KeyPair keyPair,
  List<String> hosts)
{
  /**
   * A request for a certificate within a domain. A certificate is used to
   * assign some degree of trust as to the identity of the holder of the
   * keypair.
   *
   * @param name    The name used to refer to certificate
   * @param keyPair The keypair used for the certificate
   * @param hosts   The list of hosts in the certificate
   */

  public CSCertificate
  {
    Objects.requireNonNull(name, "name");
    Objects.requireNonNull(keyPair, "keyPair");
    Objects.requireNonNull(hosts, "hosts");
  }
}
