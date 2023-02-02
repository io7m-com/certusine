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

import org.xbill.DNS.DClass;
import org.xbill.DNS.ExtendedResolver;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.NSRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.Type;

import java.io.IOException;
import java.util.ArrayList;

public final class CSDNSQueriesDJDemo
{
  private CSDNSQueriesDJDemo()
  {

  }

  public static void main(
    final String[] args)
    throws IOException
  {
    final var lookupNS =
      new Lookup(Name.fromString("io7m.com."), Type.NS, DClass.IN);

    final var nsHosts = new ArrayList<String>();
    final var nsRecords = lookupNS.run();

    if (nsRecords == null || nsRecords.length == 0) {
      throw new IllegalStateException("NS lookup failed!");
    }

    for (final var record : nsRecords) {
      if (record instanceof NSRecord nsRecord) {
        nsHosts.add(nsRecord.getTarget().toString());
      }
    }

    final var lookupTXT =
      new Lookup(Name.fromString("_acme-challenge.www.io7m.com."), Type.TXT, DClass.IN);

    lookupTXT.setResolver(new ExtendedResolver(
      nsHosts.toArray(new String[0])
    ));

    final var txtRecords = lookupTXT.run();
    if (txtRecords == null || txtRecords.length == 0) {
      throw new IllegalStateException("TXT lookup failed!");
    }
  }
}
