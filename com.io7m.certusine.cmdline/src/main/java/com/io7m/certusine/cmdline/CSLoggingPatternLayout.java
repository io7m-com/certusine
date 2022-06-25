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

package com.io7m.certusine.cmdline;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.LayoutBase;
import org.slf4j.MDC;

import java.util.Locale;

/**
 * A dynamic logging pattern based on MDC values.
 */

public final class CSLoggingPatternLayout extends LayoutBase<ILoggingEvent>
{
  /**
   * A dynamic logging pattern based on MDC values.
   */

  public CSLoggingPatternLayout()
  {

  }

  @Override
  public String doLayout(
    final ILoggingEvent event)
  {
    final var s = new StringBuilder(128);
    s.append(event.getLevel().toString().toLowerCase(Locale.ROOT));
    s.append(": ");
    // s.append(event.getLoggerName());

    final var domain = MDC.get("domain");
    if (domain != null) {
      s.append('[');
      s.append(domain);
      s.append(']');
      s.append(' ');
    }

    final var attempt = MDC.get("attempt");
    if (attempt != null) {
      s.append("(attempt ");
      s.append(attempt);
      s.append('/');
      s.append(MDC.get("attemptMax"));
      s.append(')');
      s.append(' ');
    }

    s.append(event.getFormattedMessage());
    s.append(System.lineSeparator());
    return s.toString();
  }
}
