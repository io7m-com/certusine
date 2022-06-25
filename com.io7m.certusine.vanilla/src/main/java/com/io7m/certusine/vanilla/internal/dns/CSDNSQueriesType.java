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


package com.io7m.certusine.vanilla.internal.dns;

import java.io.IOException;
import java.util.List;

/**
 * An interface that abstracts over DNS queries.
 */

public interface CSDNSQueriesType
{
  /**
   * Find the list of authoritative name servers for the given domain. The
   * domain must end with '.'.
   *
   * @param domain The domain
   *
   * @return A list of name servers
   *
   * @throws IOException On lookup failures
   */

  List<String> findAuthoritativeNameServersForDomain(String domain)
    throws IOException;

  /**
   * Find the list of TXT records for the given domain. The domain must end with
   * '.'.
   *
   * @param domain The domain
   *
   * @return A list of records
   *
   * @throws IOException On lookup failures
   */

  List<CSDNSTXTRecord> findTXTRecordsForDomain(String domain)
    throws IOException;
}
