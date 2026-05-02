/*
 * Copyright © 2026 Mark Raynsford <code@io7m.com> https://www.io7m.com
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

import com.io7m.certusine.api.CSConfigurationParameters;
import com.io7m.certusine.api.CSDNSRecordNameType;
import com.io7m.certusine.api.CSTelemetryNoOp;
import com.io7m.certusine.api.CSTelemetryServiceType;
import com.io7m.certusine.hetzner.CSHetznerDNSConfigurators;
import com.io7m.certusine.hetzner.internal.CSHetznerDNSConfigurator;
import com.io7m.jlexing.core.LexicalPosition;
import com.io7m.jlexing.core.LexicalPositions;

import java.io.IOException;
import java.nio.file.Paths;
import java.util.Map;

public final class CHetznerDNSDemo
{
  private CHetznerDNSDemo()
  {

  }

  public static void main(
    final String[] args)
    throws Exception
  {
    final var domainName =
      args[0];
    final var apiKey =
      args[1];
    final var zoneId =
      args[2];

    final var configurators =
      new CSHetznerDNSConfigurators();

    final CSHetznerDNSConfigurator configurator =
      (CSHetznerDNSConfigurator) configurators.create(
        new CSConfigurationParameters(
          Paths.get(""),
          LexicalPositions.zero(),
          Map.ofEntries(
            Map.entry("domain-name", domainName),
            Map.entry("api-key", apiKey),
            Map.entry("zone-id", zoneId)
          )
        )
      );

    final var r =
      configurator.listTXTRecords(CSTelemetryNoOp.noop());

    configurator.createTXTRecord(
      CSTelemetryNoOp.noop(),
      new CSDNSRecordNameType.CSDNSRecordNameAbsolute(
        "_acme-challenge.nonexistent.int.arc7.info."
      ),
      "valuevaluevalue"
    );
    configurator.deleteTXTRecord(
      CSTelemetryNoOp.noop(),
      new CSDNSRecordNameType.CSDNSRecordNameAbsolute(
        "_acme-challenge.nonexistent.int.arc7.info."
      ),
      "valuevaluevalue"
    );

    configurator.createTXTRecord(
      CSTelemetryNoOp.noop(),
      new CSDNSRecordNameType.CSDNSRecordNameRelative(
        "_acme-challenge.nonexistent.int"
      ),
      "valuevaluevalue"
    );
    configurator.deleteTXTRecord(
      CSTelemetryNoOp.noop(),
      new CSDNSRecordNameType.CSDNSRecordNameRelative(
        "_acme-challenge.nonexistent.int"
      ),
      "valuevaluevalue"
    );
  }
}
