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
import com.io7m.claypot.core.CLPAbstractCommand;
import com.io7m.claypot.core.CLPCommandContextType;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

import static com.io7m.claypot.core.CLPCommandType.Status.SUCCESS;
import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.CREATE_NEW;
import static java.nio.file.StandardOpenOption.TRUNCATE_EXISTING;
import static java.nio.file.StandardOpenOption.WRITE;

/**
 * Generate keypairs.
 */

@Parameters(commandDescription = "Generate keypairs.")
public final class CSGenerateKeyPair extends CLPAbstractCommand
{
  @Parameter(
    names = "--public-key",
    description = "The public key",
    required = true
  )
  private Path publicKeyFile;

  @Parameter(
    names = "--private-key",
    description = "The private key",
    required = true
  )
  private Path privateKeyFile;

  @Parameter(
    names = "--overwrite",
    arity = 1,
    description = "Overwrite keys if already present."
  )
  private boolean overwrite;

  /**
   * Construct a command.
   *
   * @param inContext The command context
   */

  public CSGenerateKeyPair(
    final CLPCommandContextType inContext)
  {
    super(inContext);
  }

  @Override
  protected Status executeActual()
    throws Exception
  {
    final var generator =
      KeyPairGenerator.getInstance("EC", "BC");

    this.privateKeyFile =
      this.privateKeyFile.toAbsolutePath();
    this.publicKeyFile =
      this.publicKeyFile.toAbsolutePath();

    generator.initialize(new ECGenParameterSpec("P-256"));

    final var keyPair = generator.generateKeyPair();

    final OpenOption[] options;
    if (this.overwrite) {
      options = new OpenOption[]{CREATE, TRUNCATE_EXISTING, WRITE};
    } else {
      options = new OpenOption[]{CREATE_NEW, WRITE};
    }

    try (var writer =
           Files.newBufferedWriter(this.publicKeyFile, options)) {
      try (var pemWriter = new JcaPEMWriter(writer)) {
        pemWriter.writeObject(keyPair.getPublic());
        pemWriter.flush();
      }
    }

    try (var writer =
           Files.newBufferedWriter(this.privateKeyFile, options)) {
      try (var pemWriter = new JcaPEMWriter(writer)) {
        pemWriter.writeObject(keyPair.getPrivate());
        pemWriter.flush();
      }
    }

    return SUCCESS;
  }

  @Override
  public String name()
  {
    return "generate-keypair";
  }
}
