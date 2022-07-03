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

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import com.io7m.certusine.api.CSCertificateName;
import com.io7m.certusine.looseleaf.CSLLCredentials;
import com.io7m.certusine.looseleaf.CSLLDownloader;
import com.io7m.claypot.core.CLPAbstractCommand;
import com.io7m.claypot.core.CLPCommandContextType;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;

import static com.io7m.claypot.core.CLPCommandType.Status.SUCCESS;

/**
 * Download certificates from looseleaf databases.
 */

@Parameters(commandDescription = "Download certificates from looseleaf databases.")
public final class CSLooseleafDownload extends CLPAbstractCommand
{
  @Parameter(
    names = "--endpoint",
    description = "The target looseleaf endpoint base.",
    required = true
  )
  private String endpoint;

  @Parameter(
    names = "--output-directory",
    description = "The output directory.",
    required = true
  )
  private Path outputDirectory;

  @Parameter(
    names = "--domain",
    description = "The domain name.",
    required = true
  )
  private String domain;

  @Parameter(
    names = "--username",
    description = "The user name.",
    required = true
  )
  private String userName;

  @Parameter(
    names = "--password",
    description = "The password.",
    required = true
  )
  private String password;

  @Parameter(
    names = "--certificate-name",
    description = "The certificate name.",
    required = true
  )
  private String certificateName;

  @Parameter(
    names = "--only-once",
    arity = 1,
    description = "Download certificates once and then exit.",
    required = false
  )
  private boolean onlyOnce;

  @Parameter(
    names = "--schedule",
    description = "Download certificates repeatedly, waiting this duration between attempts.",
    required = false,
    converter = CSDurationConverter.class
  )
  private Duration schedule = Duration.ofHours(1L);

  private CSLLDownloader downloader;

  /**
   * Construct a command.
   *
   * @param inContext The command context
   */

  public CSLooseleafDownload(
    final CLPCommandContextType inContext)
  {
    super(inContext);
  }

  @Override
  protected Status executeActual()
    throws Exception
  {
    this.downloader =
      CSLLDownloader.create(
        this.outputDirectory,
        this.endpoint,
        new CSLLCredentials(this.userName, this.password),
        this.domain,
        new CSCertificateName(this.certificateName)
      );

    while (true) {
      this.logger().info("downloading certificates from {}", this.endpoint);

      try {
        this.downloader.execute();
      } catch (final IOException e) {
        this.logger().error("i/o error: ", e);
        if (this.onlyOnce) {
          throw e;
        }
      } catch (final InterruptedException e) {
        Thread.currentThread().interrupt();
      }

      if (this.onlyOnce) {
        break;
      }

      try {
        Thread.sleep(this.schedule.toMillis());
      } catch (final InterruptedException e) {
        Thread.currentThread().interrupt();
      }
    }

    return SUCCESS;
  }

  @Override
  public String name()
  {
    return "looseleaf-download";
  }
}
