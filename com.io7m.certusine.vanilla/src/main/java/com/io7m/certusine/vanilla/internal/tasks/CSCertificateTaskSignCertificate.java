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


package com.io7m.certusine.vanilla.internal.tasks;

import com.io7m.certusine.vanilla.internal.events.CSEventCertificateSigningFailed;

/**
 * The base type of certificate signing tasks.
 */

public abstract class CSCertificateTaskSignCertificate
  extends CSCertificateTask
{
  /**
   * The base type of certificate signing tasks.
   *
   * @param inName    The task name
   * @param inContext The task context
   */

  public CSCertificateTaskSignCertificate(
    final String inName,
    final CSCertificateTaskContext inContext)
  {
    super(inName, inContext);
  }

  /**
   * A base implementation of the "completely failed" method that publishes
   * a signing failure event. This method may be overridden to raise a more
   * specific set of events if necessary.
   */

  @Override
  void executeOnTaskCompletelyFailed()
  {
    final var context = this.context();
    context.events()
      .emit(new CSEventCertificateSigningFailed(
        context.domain(),
        context.certificate().name()
      ));
  }
}
