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

import com.io7m.certusine.api.CSDNSConfiguratorType;
import com.io7m.certusine.api.CSDNSRecordNameType;
import com.io7m.certusine.api.CSTelemetryServiceType;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.Queue;

public final class CSFakeDNSConfiguratorCrashing implements CSDNSConfiguratorType
{
  private final ArrayDeque<String> requests;

  public CSFakeDNSConfiguratorCrashing()
  {
    this.requests = new ArrayDeque<>();
  }

  public Queue<String> requests()
  {
    return this.requests;
  }

  @Override
  public void createTXTRecord(
    final CSTelemetryServiceType telemetry,
    final CSDNSRecordNameType name,
    final String text)
    throws IOException
  {
    this.requests.add("CREATE " + name);
    throw new IOException();
  }

  @Override
  public void deleteTXTRecord(
    final CSTelemetryServiceType telemetry,
    final CSDNSRecordNameType recordName,
    final String recordValue)
    throws IOException
  {
    this.requests.add("DELETE " + recordName);
    throw new IOException();
  }
}
