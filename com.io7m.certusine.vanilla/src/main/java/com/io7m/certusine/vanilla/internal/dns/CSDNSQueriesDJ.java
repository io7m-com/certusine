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

import com.io7m.jaffirm.core.Preconditions;
import org.xbill.DNS.DClass;
import org.xbill.DNS.ExtendedResolver;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.NSRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * A DNS query implementation based on {@code dnsjava}.
 */

public final class CSDNSQueriesDJ implements CSDNSQueriesType
{
  private final List<String> nameServers;

  /**
   * A DNS query implementation based on {@code dnsjava}.
   *
   * @param inNames The name servers to use for queries
   */

  public CSDNSQueriesDJ(
    final List<String> inNames)
  {
    this.nameServers = Objects.requireNonNull(inNames, "names");
  }

  @Override
  public List<String> findAuthoritativeNameServersForDomain(
    final String domain)
    throws IOException
  {
    Preconditions.checkPreconditionV(
      domain.endsWith("."),
      "Domain " + domain + " must end with '.'"
    );

    final var lookup =
      new Lookup(Name.fromString(domain), Type.NS, DClass.IN);

    if (!this.nameServers.isEmpty()) {
      lookup.setResolver(new ExtendedResolver(
        this.nameServers.toArray(new String[0])
      ));
    }

    final var nsRecords = lookup.run();
    if (nsRecords != null) {
      final var nsHosts = new ArrayList<String>();
      for (final var record : nsRecords) {
        if (record instanceof NSRecord nsRecord) {
          nsHosts.add(nsRecord.getTarget().toString());
        }
      }
      return nsHosts;
    }

    throw new IOException(lookup.getErrorString());
  }

  @Override
  public List<CSDNSTXTRecord> findTXTRecordsForDomain(
    final String domain)
    throws IOException
  {
    Preconditions.checkPreconditionV(
      domain.endsWith("."),
      "Domain " + domain + " must end with '.'"
    );

    final var lookup =
      new Lookup(Name.fromString(domain), Type.TXT, DClass.IN);

    if (!this.nameServers.isEmpty()) {
      lookup.setResolver(new ExtendedResolver(
        this.nameServers.toArray(new String[0])
      ));
    }

    final var records = lookup.run();
    if (records != null) {
      final var results = new ArrayList<CSDNSTXTRecord>();
      for (final var record : records) {
        if (record instanceof TXTRecord txtRecord) {
          results.add(
            new CSDNSTXTRecord(
              txtRecord.getName().toString(),
              txtRecord.rdataToString()
            )
          );
        }
      }
      return List.copyOf(results);
    }
    return List.of();
  }
}
