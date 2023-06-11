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

package com.io7m.certusine.vanilla;

import com.io7m.certusine.api.CSDomain;
import com.io7m.certusine.api.CSOptions;
import com.io7m.certusine.api.CSTelemetryServiceType;
import com.io7m.certusine.certstore.api.CSCertificateStoreType;
import com.io7m.certusine.vanilla.internal.CSDomainExecutor;
import com.io7m.certusine.vanilla.internal.CSStrings;
import com.io7m.certusine.vanilla.internal.events.CSEventServiceType;
import com.io7m.repetoir.core.RPServiceDirectoryType;
import org.shredzone.acme4j.Session;

import java.io.IOException;
import java.time.Clock;
import java.util.Objects;

/**
 * Functions to process domains.
 */

public final class CSDomains
{
  private CSDomains()
  {

  }

  /**
   * Renew all certificates for the given domain.
   *
   * @param services         A service directory
   * @param options          The execution options
   * @param domain           The domain
   * @param certificateStore The certificate store
   * @param clock            The clock used for time-based operations
   *
   * @throws IOException          On errors
   * @throws InterruptedException On interruption
   */

  public static void renew(
    final RPServiceDirectoryType services,
    final CSOptions options,
    final CSDomain domain,
    final Clock clock,
    final CSCertificateStoreType certificateStore)
    throws IOException, InterruptedException
  {
    Objects.requireNonNull(services, "services");
    Objects.requireNonNull(options, "options");
    Objects.requireNonNull(domain, "domain");
    Objects.requireNonNull(clock, "clock");
    Objects.requireNonNull(certificateStore, "certificateStore");

    new CSDomainExecutor(
      services.requireService(CSStrings.class),
      services.requireService(CSTelemetryServiceType.class),
      services.requireService(CSEventServiceType.class),
      options,
      domain,
      clock,
      certificateStore,
      acmeInformation -> {
        return new Session(acmeInformation.acmeURI());
      }
    ).execute();
  }
}
