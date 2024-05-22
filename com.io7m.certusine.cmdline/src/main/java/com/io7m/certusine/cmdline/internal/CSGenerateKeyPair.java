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

import com.io7m.quarrel.core.QCommandContextType;
import com.io7m.quarrel.core.QCommandMetadata;
import com.io7m.quarrel.core.QCommandStatus;
import com.io7m.quarrel.core.QCommandType;
import com.io7m.quarrel.core.QParameterNamed1;
import com.io7m.quarrel.core.QParameterNamedType;
import com.io7m.quarrel.core.QStringType.QConstant;
import com.io7m.quarrel.ext.logback.QLogback;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.List;
import java.util.Optional;

import static java.lang.Boolean.FALSE;
import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.CREATE_NEW;
import static java.nio.file.StandardOpenOption.TRUNCATE_EXISTING;
import static java.nio.file.StandardOpenOption.WRITE;

/**
 * Generate keypairs.
 */

public final class CSGenerateKeyPair implements QCommandType
{
  private static final QParameterNamed1<Path> PUBLIC_KEY_FILE =
    new QParameterNamed1<>(
      "--public-key",
      List.of(),
      new QConstant("The public key"),
      Optional.empty(),
      Path.class
    );

  private static final QParameterNamed1<Path> PRIVATE_KEY_FILE =
    new QParameterNamed1<>(
      "--private-key",
      List.of(),
      new QConstant("The private key"),
      Optional.empty(),
      Path.class
    );

  private static final QParameterNamed1<Boolean> OVERWRITE =
    new QParameterNamed1<>(
      "--overwrite",
      List.of(),
      new QConstant("Overwrite keys if already present."),
      Optional.of(FALSE),
      Boolean.class
    );

  private final QCommandMetadata metadata;

  /**
   * Construct a command.
   */

  public CSGenerateKeyPair()
  {
    this.metadata = new QCommandMetadata(
      "generate-keypair",
      new QConstant("Generate keypairs."),
      Optional.empty()
    );
  }

  @Override
  public List<QParameterNamedType<?>> onListNamedParameters()
  {
    return QLogback.plusParameters(
      List.of(PUBLIC_KEY_FILE, PRIVATE_KEY_FILE, OVERWRITE)
    );
  }

  @Override
  public QCommandStatus onExecute(
    final QCommandContextType context)
    throws Exception
  {
    QLogback.configure(context);

    Security.addProvider(new BouncyCastleProvider());

    final var generator =
      KeyPairGenerator.getInstance("EC", "BC");

    final var privateKeyFile =
      context.parameterValue(PRIVATE_KEY_FILE).toAbsolutePath();
    final var publicKeyFile =
      context.parameterValue(PUBLIC_KEY_FILE).toAbsolutePath();

    generator.initialize(new ECGenParameterSpec("P-256"));

    final var keyPair = generator.generateKeyPair();

    final OpenOption[] options;
    if (context.parameterValue(OVERWRITE).booleanValue()) {
      options = new OpenOption[]{CREATE, TRUNCATE_EXISTING, WRITE};
    } else {
      options = new OpenOption[]{CREATE_NEW, WRITE};
    }

    try (var writer = Files.newBufferedWriter(publicKeyFile, options)) {
      try (var pemWriter = new JcaPEMWriter(writer)) {
        pemWriter.writeObject(keyPair.getPublic());
        pemWriter.flush();
      }
    }

    try (var writer = Files.newBufferedWriter(privateKeyFile, options)) {
      try (var pemWriter = new JcaPEMWriter(writer)) {
        pemWriter.writeObject(keyPair.getPrivate());
        pemWriter.flush();
      }
    }

    return QCommandStatus.SUCCESS;
  }

  @Override
  public QCommandMetadata metadata()
  {
    return this.metadata;
  }
}
