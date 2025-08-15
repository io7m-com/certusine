/*
 * Copyright © 2025 Mark Raynsford <code@io7m.com> https://www.io7m.com
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


import com.io7m.certusine.api.CSConfigurationServiceType;
import com.io7m.certusine.certstore.api.CSCertificateStored;
import com.io7m.certusine.vanilla.internal.store.CSCertificateStoreServiceType;
import com.io7m.repetoir.core.RPServiceDirectoryType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.HashSet;

/**
 * Certificate utilities for clients.
 */

public final class CSCertificateUtilities
{
  private static final Logger LOG =
    LoggerFactory.getLogger(CSCertificateUtilities.class);

  private CSCertificateUtilities()
  {

  }

  /**
   * Delete any unused certificates from the database.
   *
   * @param services The service directory
   *
   * @throws IOException On errors
   */

  public static void cleanUpUnusedCertificates(
    final RPServiceDirectoryType services)
    throws IOException
  {
    final var configuration =
      services.requireService(CSConfigurationServiceType.class)
        .configuration();

    if (!configuration.options().dropUnreferencedCertificates()) {
      return;
    }

    LOG.debug("Cleaning up unused certificates.");

    final var store =
      services.requireService(CSCertificateStoreServiceType.class)
        .store();

    final var toRemove =
      new HashSet<CSCertificateStored>();
    final var domains =
      configuration.domains();
    final var existing =
      store.all();

    for (final var existingCertificate : existing) {
      final var domain = domains.get(existingCertificate.domain());
      if (domain == null) {
        toRemove.add(existingCertificate);
        continue;
      }

      final var certificates =
        domain.certificates();
      final var cert =
        certificates.get(existingCertificate.name().value());

      if (cert == null) {
        toRemove.add(existingCertificate);
        continue;
      }

      LOG.debug(
        "Keeping certificate: {} {}",
        domain.domain(),
        cert.name().value()
      );
    }

    for (final var remove : toRemove) {
      LOG.debug(
        "Deleting unreferenced certificate: {} {}",
        remove.domain(),
        remove.name().value()
      );
      store.delete(remove.domain(), remove.name());
    }
  }
}
