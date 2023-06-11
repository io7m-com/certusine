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


package com.io7m.certusine.vanilla.internal.tasks;

import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType.CSCertificateTaskCompleted;
import com.io7m.certusine.vanilla.internal.tasks.CSCertificateTaskStatusType.CSCertificateTaskInProgress;
import io.opentelemetry.api.trace.Span;
import org.shredzone.acme4j.Order;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;

import static com.io7m.certusine.vanilla.internal.tasks.CSDurations.ACME_UPDATE_PAUSE_TIME;

/**
 * A certificate task that checks if DNS records have been created.
 */

public final class CSCertificateTaskAuthorizeDNSCheckRecords
  extends CSCertificateTaskAuthorizeDNS
{
  private static final Logger LOG =
    LoggerFactory.getLogger(CSCertificateTaskAuthorizeDNSCheckRecords.class);

  private final Order order;
  private final Map<String, String> expectedTXTRecords;

  /**
   * A certificate task that checks if DNS records have been created.
   *
   * @param inContext            The task execution context
   * @param inOrder              The certificate order
   * @param inExpectedTXTRecords The expected TXT records
   */

  public CSCertificateTaskAuthorizeDNSCheckRecords(
    final CSCertificateTaskContext inContext,
    final Order inOrder,
    final Map<String, String> inExpectedTXTRecords)
  {
    super("AuthorizeDNSCheckRecords", inContext);

    this.order =
      Objects.requireNonNull(inOrder, "order");
    this.expectedTXTRecords =
      Objects.requireNonNull(inExpectedTXTRecords, "expectedTXTRecords");
  }

  @Override
  CSCertificateTaskStatusType executeActual()
  {
    LOG.debug("checking that DNS TXT records are visible");

    var foundAll = true;

    final var context = this.context();
    for (final var entry : this.expectedTXTRecords.entrySet()) {
      try {
        final var domainName = entry.getKey();
        final var recordText = entry.getValue();

        /*
         * Look up the authoritative nameservers for the domain. ACME
         * implementations will typically look at these servers in order to
         * locate TXT records, so if we can find the records, the ACME
         * implementations probably can too.
         */

        final var dnsQueries =
          context.dnsQueries();

        final var nsHosts =
          dnsQueries.withDefaultNameServers()
            .findAuthoritativeNameServersForDomain(context.domain().domain() + ".");

        LOG.debug("located nameservers {} for {}", nsHosts, domainName);

        final var recordName =
          this.txtRecordNameToQuery(domainName);
        final var txtRecords =
          dnsQueries.withNameServers(nsHosts)
            .findTXTRecordsForDomain(recordName);

        LOG.debug("checking that TXT record {} is visible", recordName);
        var found = false;
        LOG.debug("received {} records", Integer.valueOf(txtRecords.size()));

        /*
         * The values returned in TXT records will be quoted. Therefore,
         * the expected text value needs to be quoted too, otherwise the
         * comparison will never succeed.
         */

        final var expectedText = "\"%s\"".formatted(recordText);
        for (final var record : txtRecords) {
          final var receivedText = record.value();
          if (receivedText.equals(expectedText)) {
            LOG.debug("found matching TXT record for domain {}", domainName);
            found = true;
            break;
          }
        }

        if (found) {
          LOG.debug("TXT record {} is visible", recordName);
        } else {
          LOG.debug("TXT record {} is not yet visible", recordName);
        }

        foundAll &= found;
      } catch (final IOException e) {
        LOG.error("i/o error: {}", e.getMessage());
        Span.current().recordException(e);
        foundAll = false;
      }
    }

    if (foundAll) {
      LOG.debug("all required TXT records were located");
      return new CSCertificateTaskCompleted(
        OptionalLong.empty(),
        Optional.of(
          new CSCertificateTaskAuthorizeDNSTriggerChallenges(
            context,
            this.order)
        )
      );
    }

    LOG.debug("at least one TXT record is not yet visible");
    return new CSCertificateTaskInProgress(ACME_UPDATE_PAUSE_TIME);
  }
}
