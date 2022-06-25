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
import java.util.Optional;
import java.util.OptionalLong;

/**
 * The status of a task execution.
 */

public sealed interface CSCertificateTaskStatusType
{
  /**
   * @return The status is a failure
   */

  boolean isFailure();

  /**
   * @return The delay required until the next time this task is retried, or the
   * next task is executed
   */

  OptionalLong delayRequired();

  /**
   * The task failed permanently and retrying will not result in success.
   *
   * @param exception The exception raised
   */

  record CSCertificateTaskFailedPermanently(
    Exception exception)
    implements CSCertificateTaskStatusType
  {
    /**
     * The task failed permanently and retrying will not result in success.
     */

    public CSCertificateTaskFailedPermanently
    {
      Objects.requireNonNull(exception, "exception");
    }

    @Override
    public boolean isFailure()
    {
      return true;
    }

    @Override
    public OptionalLong delayRequired()
    {
      return OptionalLong.empty();
    }
  }

  /**
   * The task failed, but might succeed if it is retried.
   *
   * @param delayRequired The delay required before retrying
   * @param exception     The exception raised
   */

  record CSCertificateTaskFailedButCanBeRetried(
    OptionalLong delayRequired,
    Exception exception)
    implements CSCertificateTaskStatusType
  {
    /**
     * The task failed, but might succeed if it is retried.
     */

    public CSCertificateTaskFailedButCanBeRetried
    {
      Objects.requireNonNull(delayRequired, "delayRequired");
      Objects.requireNonNull(exception, "exception");
    }

    @Override
    public boolean isFailure()
    {
      return true;
    }
  }

  /**
   * The task is in progress and should be retried.
   *
   * @param delayRequired The delay required before retrying
   */

  record CSCertificateTaskInProgress(
    OptionalLong delayRequired)
    implements CSCertificateTaskStatusType
  {
    /**
     * The task is in progress and should be retried.
     */

    public CSCertificateTaskInProgress
    {
      Objects.requireNonNull(delayRequired, "delayRequired");
    }

    @Override
    public boolean isFailure()
    {
      return false;
    }
  }

  /**
   * The task is completed.
   *
   * @param delayRequired The delay required before the next task is executed
   * @param next          The next task, if any
   */

  record CSCertificateTaskCompleted(
    OptionalLong delayRequired,
    Optional<CSCertificateTask> next)
    implements CSCertificateTaskStatusType
  {
    /**
     * The task is completed.
     */

    public CSCertificateTaskCompleted
    {
      Objects.requireNonNull(delayRequired, "delayRequired");
      Objects.requireNonNull(next, "next");
    }

    @Override
    public boolean isFailure()
    {
      return false;
    }
  }
}
