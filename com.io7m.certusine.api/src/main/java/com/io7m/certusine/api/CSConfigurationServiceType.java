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


package com.io7m.certusine.api;

import com.io7m.repetoir.core.RPServiceType;

import java.util.concurrent.Flow;

/**
 * A service that frequently reloads a configuration, and always
 * returns the most recently successfully loaded configuration.
 */

public interface CSConfigurationServiceType extends RPServiceType, AutoCloseable
{
  /**
   * @return The most recent configuration
   */

  CSConfiguration configuration();

  /**
   * Reload the configuration.
   */

  void reload();

  /**
   * @return An event stream that publishes a stream of distinct configuration values
   */

  Flow.Publisher<CSConfiguration> events();
}
