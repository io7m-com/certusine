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

import com.io7m.certusine.vanilla.internal.dns.CSDNSQueriesDJ;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertTrue;

public final class CSDNSQueriesDJTest
{
  @Test
  public void testQueryTXT()
    throws IOException
  {
    final var queries =
      new CSDNSQueriesDJ(List.of())
        .findTXTRecordsForDomain("example.com.");

    /*
     * This test will break if example.com changes it's SPF settings!
     */

    assertTrue(
      queries.stream()
        .anyMatch(r -> {
          return Objects.equals(r.value(), "\"v=spf1 -all\"");
        })
    );
  }

  @Test
  public void testQueryNS()
    throws IOException
  {
    final var queries =
      new CSDNSQueriesDJ(List.of())
        .findAuthoritativeNameServersForDomain("example.com.");

    /*
     * This test will break if example.com changes it's authoritative
     * servers.
     */

    assertTrue(queries.contains("a.iana-servers.net."));
  }
}
