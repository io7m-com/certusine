/*
 * Copyright © 2023 Mark Raynsford <code@io7m.com> https://www.io7m.com
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

import com.io7m.certusine.api.CSCertificateOutputProviderType;
import com.io7m.certusine.api.CSDNSConfiguratorProviderType;
import com.io7m.certusine.api.CSTelemetryServiceType;
import com.io7m.certusine.certstore.api.CSCertificateStoreFactoryType;
import com.io7m.certusine.vanilla.internal.CSStrings;
import com.io7m.certusine.vanilla.internal.events.CSEventService;
import com.io7m.certusine.vanilla.internal.events.CSEventServiceType;
import com.io7m.repetoir.core.RPServiceDirectory;
import com.io7m.repetoir.core.RPServiceDirectoryWritableType;

import java.io.IOException;
import java.util.Locale;
import java.util.ServiceLoader;

/**
 * The main service directory.
 */

public final class CSServices
{
  private CSServices()
  {

  }

  /**
   * The main service directory.
   *
   * @param locale    The locale
   * @param telemetry The telemetry service
   *
   * @return A service directory
   *
   * @throws IOException On errors
   */

  public static RPServiceDirectoryWritableType create(
    final Locale locale,
    final CSTelemetryServiceType telemetry)
    throws IOException
  {
    final var directory = new RPServiceDirectory();

    ServiceLoader.load(CSDNSConfiguratorProviderType.class)
      .stream()
      .map(ServiceLoader.Provider::get)
      .forEach(s -> directory.register(CSDNSConfiguratorProviderType.class, s));

    ServiceLoader.load(CSCertificateOutputProviderType.class)
      .stream()
      .map(ServiceLoader.Provider::get)
      .forEach(s -> directory.register(
        CSCertificateOutputProviderType.class,
        s));

    ServiceLoader.load(CSCertificateStoreFactoryType.class)
      .stream()
      .map(ServiceLoader.Provider::get)
      .forEach(s -> directory.register(CSCertificateStoreFactoryType.class, s));

    directory.register(CSTelemetryServiceType.class, telemetry);
    directory.register(
      CSEventServiceType.class,
      CSEventService.create(telemetry));
    directory.register(CSStrings.class, new CSStrings(locale));
    return directory;
  }
}
