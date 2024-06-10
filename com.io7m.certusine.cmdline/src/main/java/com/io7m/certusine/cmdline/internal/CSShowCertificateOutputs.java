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


package com.io7m.certusine.cmdline.internal;

import com.io7m.certusine.api.CSCertificateOutputProviderType;
import com.io7m.quarrel.core.QCommandContextType;
import com.io7m.quarrel.core.QCommandMetadata;
import com.io7m.quarrel.core.QCommandStatus;
import com.io7m.quarrel.core.QCommandType;
import com.io7m.quarrel.core.QParameterNamedType;
import com.io7m.quarrel.core.QStringType.QConstant;
import com.io7m.quarrel.ext.logback.QLogback;

import java.util.List;
import java.util.Optional;
import java.util.ServiceLoader;

/**
 * Show supported certificate outputs.
 */

public final class CSShowCertificateOutputs implements QCommandType
{
  private final QCommandMetadata metadata;

  /**
   * Construct a command.
   */

  public CSShowCertificateOutputs()
  {
    this.metadata = new QCommandMetadata(
      "show-certificate-outputs",
      new QConstant("Show supported certificate outputs."),
      Optional.empty()
    );
  }

  @Override
  public List<QParameterNamedType<?>> onListNamedParameters()
  {
    return QLogback.parameters();
  }

  @Override
  public QCommandStatus onExecute(
    final QCommandContextType context)
  {
    QLogback.configure(context);

    final var iter =
      ServiceLoader.load(CSCertificateOutputProviderType.class)
        .iterator();

    final var output = context.output();
    while (iter.hasNext()) {
      final var dns = iter.next();
      output.printf("%s : %s%n", dns.name(), dns.description());
    }

    output.flush();
    return QCommandStatus.SUCCESS;
  }

  @Override
  public QCommandMetadata metadata()
  {
    return this.metadata;
  }
}
