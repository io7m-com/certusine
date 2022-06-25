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

package com.io7m.certusine.tests;

import com.io7m.certusine.api.CSCertificateName;
import com.io7m.certusine.api.CSCertificateOutputData;
import com.io7m.certusine.api.CSConfigurationException;
import com.io7m.certusine.api.CSConfigurationParameters;
import com.io7m.certusine.etcd.CSEtcdOutputProvider;
import com.io7m.jlexing.core.LexicalPositions;
import io.etcd.jetcd.ByteSequence;
import io.etcd.jetcd.Client;
import io.etcd.jetcd.test.EtcdClusterExtension;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ExecutionException;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public final class CSEtcdOutputTest
{
  private static final Logger LOG =
    LoggerFactory.getLogger(CSEtcdOutputTest.class);

  private Path directory;
  private CSEtcdOutputProvider outputs;
  private CSFakeEtcdServer server;

  @RegisterExtension
  public static final EtcdClusterExtension ETCD_CLUSTER =
    EtcdClusterExtension.builder()
      .withNodes(1)
      .build();

  @BeforeEach
  public void setup()
    throws Exception
  {
    this.server =
      CSFakeEtcdServer.create(20000);
    this.directory =
      CSTestDirectories.createTempDirectory();
    this.outputs =
      new CSEtcdOutputProvider();
  }

  @AfterEach
  public void tearDown()
    throws Exception
  {
    CSTestDirectories.deleteDirectory(this.directory);
    this.server.close();
  }

  @Test
  public void testMisconfigured()
    throws CSConfigurationException
  {
    final var ex =
      assertThrows(CSConfigurationException.class, () -> {
        this.outputs.create(
          "example",
          new CSConfigurationParameters(
            this.directory,
            LexicalPositions.zero(),
            Map.ofEntries()
          )
        );
      });

    LOG.debug("exception: ", ex);
    assertTrue(
      ex.errors()
        .stream()
        .anyMatch(e -> Objects.equals(
          e.errorCode(),
          "error-parameter-required"))
    );
  }

  @Test
  @Disabled("etcd is unreliable")
  public void testUnauthenticatedWrite()
    throws Exception
  {
    final var output =
      this.outputs.create(
        "example",
        new CSConfigurationParameters(
          this.directory,
          LexicalPositions.zero(),
          Map.ofEntries(
            Map.entry(
              "endpoint",
              ETCD_CLUSTER.clientEndpoints().get(0).toString())
          )
        )
      );

    output.write(new CSCertificateOutputData(
      "example.com",
      new CSCertificateName("www"),
      "PUB",
      "PRI",
      "CERT",
      "CERTCHAIN"
    ));

    this.checkKeysAndValues(false);
  }

  private void checkKeysAndValues(
    final boolean authenticated)
    throws InterruptedException, ExecutionException
  {
    final var clientBuilder =
      Client.builder()
        .endpoints(ETCD_CLUSTER.clientEndpoints());

    if (authenticated) {
      clientBuilder.user(ByteSequence.from("root", UTF_8));
      clientBuilder.password(ByteSequence.from("12345678", UTF_8));
    }

    try (var client = clientBuilder.build()) {
      final var kv = client.getKVClient();
      assertEquals(
        "PUB",
        kv.get(ByteSequence.from(
            "/certificates/example.com/www/public_key",
            UTF_8))
          .get()
          .getKvs()
          .get(0)
          .getValue()
          .toString()
      );

      assertEquals(
        "PRI",
        kv.get(ByteSequence.from(
            "/certificates/example.com/www/private_key",
            UTF_8))
          .get()
          .getKvs()
          .get(0)
          .getValue()
          .toString()
      );

      assertEquals(
        "CERT",
        kv.get(ByteSequence.from(
            "/certificates/example.com/www/certificate",
            UTF_8))
          .get()
          .getKvs()
          .get(0)
          .getValue()
          .toString()
      );

      assertEquals(
        "CERTCHAIN",
        kv.get(ByteSequence.from(
            "/certificates/example.com/www/certificate_full_chain",
            UTF_8))
          .get()
          .getKvs()
          .get(0)
          .getValue()
          .toString()
      );
    }
  }

  @Test
  @Disabled("etcd is unreliable")
  public void testAuthenticatedWrite()
    throws Exception
  {
    final var output =
      this.outputs.create(
        "example",
        new CSConfigurationParameters(
          this.directory,
          LexicalPositions.zero(),
          Map.ofEntries(
            Map.entry(
              "endpoint",
              ETCD_CLUSTER.clientEndpoints().get(0).toString()),
            Map.entry("username", "root"),
            Map.entry("password", "12345678")
          )
        )
      );

    createRootUserAndEnableAuthentication();

    output.write(new CSCertificateOutputData(
      "example.com",
      new CSCertificateName("www"),
      "PUB",
      "PRI",
      "CERT",
      "CERTCHAIN"
    ));

    this.checkKeysAndValues(true);
  }

  @Test
  @Disabled("etcd is unreliable")
  public void testAuthenticatedWriteWrongPassword()
    throws Exception
  {
    final var output =
      this.outputs.create(
        "example",
        new CSConfigurationParameters(
          this.directory,
          LexicalPositions.zero(),
          Map.ofEntries(
            Map.entry(
              "endpoint",
              ETCD_CLUSTER.clientEndpoints().get(0).toString()),
            Map.entry("username", "root"),
            Map.entry("password", "WRONG!")
          )
        )
      );

    createRootUserAndEnableAuthentication();

    final var ex = assertThrows(IOException.class, () -> {
      output.write(new CSCertificateOutputData(
        "example.com",
        new CSCertificateName("www"),
        "PUB",
        "PRI",
        "CERT",
        "CERTCHAIN"
      ));
    });
  }

  private static void createRootUserAndEnableAuthentication()
    throws InterruptedException, ExecutionException
  {
    try (var client =
           Client.builder()
             .endpoints(ETCD_CLUSTER.clientEndpoints())
             .build()) {

      final var auth = client.getAuthClient();
      auth.userAdd(
          ByteSequence.from("root", UTF_8),
          ByteSequence.from("12345678", UTF_8))
        .get();

      auth.userGrantRole(
        ByteSequence.from("root", UTF_8),
        ByteSequence.from("root", UTF_8));

      auth.authEnable()
        .get();

      Thread.sleep(1_000L);
    }
  }
}
