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

import java.util.Objects;

/**
 * An exception raised by a certificate task.
 */

public final class CSCertificateTaskException extends Exception
{
  private final boolean canRetry;

  /**
   * Create an exception.
   *
   * @param message    The exception message
   * @param inCanRetry {@code true} if the operation could be retried
   */

  public CSCertificateTaskException(
    final String message,
    final boolean inCanRetry)
  {
    super(Objects.requireNonNull(message, "message"));
    this.canRetry = inCanRetry;
  }

  /**
   * Create an exception.
   *
   * @param message    The exception message
   * @param cause      The cause
   * @param inCanRetry {@code true} if the operation could be retried
   */

  public CSCertificateTaskException(
    final String message,
    final Throwable cause,
    final boolean inCanRetry)
  {
    super(
      Objects.requireNonNull(message, "message"),
      Objects.requireNonNull(cause, "cause"));
    this.canRetry = inCanRetry;
  }

  /**
   * Create an exception.
   *
   * @param cause      The cause
   * @param inCanRetry {@code true} if the operation could be retried
   */

  public CSCertificateTaskException(
    final Throwable cause,
    final boolean inCanRetry)
  {
    super(Objects.requireNonNull(cause, "cause"));
    this.canRetry = inCanRetry;
  }

  /**
   * @return {@code true} if the operation could be retried
   */

  public boolean canRetry()
  {
    return this.canRetry;
  }
}
