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

/**
 * Fault injection configuration.
 *
 * @param failTasks                Fail task execution
 * @param failDNSChallenge         Fail DNS challenges
 * @param failSigningCertificates  Fail signing certificates
 * @param crashTasks               Crash task execution
 * @param crashDNSChallenge        Crash DNS challenges
 * @param crashSigningCertificates Crash signing certificates
 */

public record CSFaultInjectionConfiguration(
  boolean failTasks,
  boolean failDNSChallenge,
  boolean failSigningCertificates,
  boolean crashTasks,
  boolean crashDNSChallenge,
  boolean crashSigningCertificates)
{
  private static final CSFaultInjectionConfiguration DISABLED =
    new CSFaultInjectionConfiguration(
      false,
      false,
      false,
      false,
      false,
      false
    );

  /**
   * @return The "completely disabled" fault injection configuration
   */

  public static CSFaultInjectionConfiguration disabled()
  {
    return DISABLED;
  }
}
