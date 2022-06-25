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

import com.io7m.certusine.etcd.internal.CSEtcdMessages;
import com.io7m.certusine.etcd.internal.dto.CSEMessageType;
import com.io7m.certusine.etcd.internal.dto.CSEMessageType.CERequestPut;
import com.io7m.certusine.etcd.internal.dto.CSEMessageType.CSEAuthenticate;
import com.io7m.certusine.etcd.internal.dto.CSEMessageType.CSEAuthenticateResponse;
import com.io7m.certusine.etcd.internal.dto.CSEMessageType.CSEAuthenticateResponseHeader;
import com.io7m.certusine.etcd.internal.dto.CSEMessageType.CSEError;
import com.io7m.certusine.etcd.internal.dto.CSEMessageType.CSETransaction;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;

public final class CSEtcdMessagesTest
{
  private static final Logger LOG =
    LoggerFactory.getLogger(CSEtcdMessagesTest.class);

  private CSEtcdMessages messages;

  @BeforeEach
  public void setup()
  {
    this.messages = new CSEtcdMessages();
  }

  @AfterEach
  public void tearDown()
  {

  }

  @Test
  public void testAuthenticate()
    throws Exception
  {
    final var m0 =
      new CSEAuthenticate("user", "pass");
    final var data =
      this.messages.serialize(m0);

    LOG.debug("{}", new String(data, UTF_8));

    final var m1 =
      this.messages.deserialize(data);

    assertEquals(m0, m1);
  }

  @Test
  public void testAuthenticateText()
    throws Exception
  {
    final var data =
      """
        {"name":"user","password":"pass"}
              """.getBytes(UTF_8);
    final var m1 =
      this.messages.deserialize(data);

    assertEquals(new CSEAuthenticate(
      "user",
      "pass"
    ), m1);
  }

  @Test
  public void testErrorText()
    throws Exception
  {
    final var data =
      """
        {"error":"etcdserver: authentication failed, invalid user ID or password","code":3,"message":"etcdserver: authentication failed, invalid user ID or password"}
              """.getBytes(UTF_8);
    final var m1 =
      this.messages.deserialize(data);

    assertEquals(new CSEError(
      "etcdserver: authentication failed, invalid user ID or password",
      BigInteger.valueOf(3L),
      "etcdserver: authentication failed, invalid user ID or password"
    ), m1);
  }

  @Test
  public void testError()
    throws Exception
  {
    final var m0 =
      new CSEAuthenticate("user", "pass");
    final var data =
      this.messages.serialize(m0);
    final var m1 =
      this.messages.deserialize(data);

    assertEquals(m0, m1);
  }

  @Test
  public void testAuthenticateResponse()
    throws Exception
  {
    final var m0 =
      new CSEAuthenticateResponse(
        new CSEAuthenticateResponseHeader(
          "cluster",
          "member",
          "1",
          "raft"),
        "abcd");
    final var data =
      this.messages.serialize(m0);

    LOG.debug("{}", new String(data, UTF_8));

    final var m1 =
      this.messages.deserialize(data);

    assertEquals(m0, m1);
  }

  @Test
  public void testAuthenticateResponseText()
    throws Exception
  {
    final var data =
      """
        {"header":{"cluster_id":"14841639068965178418","member_id":"10276657743932975437","revision":"1","raft_term":"4"},"token":"NWFicrQSAidJoDIl.23"}
              """.getBytes(UTF_8);
    final var m1 =
      this.messages.deserialize(data);

    assertEquals(new CSEAuthenticateResponse(
      new CSEAuthenticateResponseHeader(
        "14841639068965178418",
        "10276657743932975437",
        "1",
        "4"),
      "NWFicrQSAidJoDIl.23"
    ), m1);
  }

  @Test
  public void testTransaction()
    throws Exception
  {
    final var m0 =
      new CSETransaction(
        List.of(),
        List.of(
          new CERequestPut(new CSEMessageType.CEKV("azAK", "djAK"))
        )
      );

    final var data =
      this.messages.serialize(m0);

    LOG.debug("{}", new String(data, UTF_8));

    final var m1 =
      this.messages.deserialize(data);

    assertEquals(m0, m1);
  }
}
