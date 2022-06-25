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

import java.nio.file.Path;
import java.time.Duration;
import java.util.Objects;

/**
 * The options associated with the ACME process.
 *
 * @param certificateStore               The local certificate store used to
 *                                       hold persistent certificate state
 *                                       during processing
 * @param dnsWaitTime                    The amount of time to wait after DNS
 *                                       records have been created before asking
 *                                       the ACME server to check them.
 * @param certificateExpirationThreshold The expiration threshold for
 *                                       certificates; if a certificate has less
 *                                       than or equal this time remaining
 *                                       before it expires, renewal should
 *                                       proceed
 */

public record CSOptions(
  Path certificateStore,
  Duration dnsWaitTime,
  Duration certificateExpirationThreshold)
{
  /**
   * The options associated with the ACME process.
   *
   * @param certificateStore               The local certificate store used to
   *                                       hold persistent certificate state
   *                                       during processing
   * @param dnsWaitTime                    The amount of time to wait after DNS
   *                                       records have been created before
   *                                       asking the ACME server to check
   *                                       them.
   * @param certificateExpirationThreshold The expiration threshold for
   *                                       certificates; if a certificate has
   *                                       less than or equal this time
   *                                       remaining before it expires, renewal
   *                                       should proceed
   */

  public CSOptions
  {
    Objects.requireNonNull(
      certificateStore, "certificateStore");
    Objects.requireNonNull(
      dnsWaitTime, "dnsWaitTime");
    Objects.requireNonNull(
      certificateExpirationThreshold, "certificateExpirationThreshold");
  }
}
