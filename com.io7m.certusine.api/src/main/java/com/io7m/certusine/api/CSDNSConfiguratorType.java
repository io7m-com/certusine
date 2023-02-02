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

import java.io.IOException;

/**
 * The type of DNS configurators that know how to create DNS records.
 */

public interface CSDNSConfiguratorType
{
  /**
   * Create a TXT record with the given text.
   *
   * @param recordName  The record name
   * @param recordValue The text
   *
   * @throws IOException          On errors
   * @throws InterruptedException On thread interruption
   */

  void createTXTRecord(
    CSDNSRecordNameType recordName,
    String recordValue)
    throws IOException, InterruptedException;

  /**
   * Delete a TXT record with the given text.
   *
   * @param recordName  The record name
   * @param recordValue The text
   *
   * @throws IOException          On errors
   * @throws InterruptedException On thread interruption
   */

  void deleteTXTRecord(
    CSDNSRecordNameType recordName,
    String recordValue)
    throws IOException, InterruptedException;
}
