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


package com.io7m.certusine.etcd.internal;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.module.SimpleDeserializers;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.io7m.certusine.etcd.internal.dto.CSEMessageType;
import com.io7m.certusine.etcd.internal.dto.CSEMessageType.CSETransaction;
import com.io7m.dixmont.core.DmJsonRestrictedDeserializers;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;

import static com.fasterxml.jackson.databind.DeserializationFeature.USE_BIG_INTEGER_FOR_INTS;
import static com.fasterxml.jackson.databind.MapperFeature.SORT_PROPERTIES_ALPHABETICALLY;
import static com.fasterxml.jackson.databind.SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS;
import static com.io7m.certusine.etcd.internal.dto.CSEMessageType.CEKV;
import static com.io7m.certusine.etcd.internal.dto.CSEMessageType.CERequestPut;
import static com.io7m.certusine.etcd.internal.dto.CSEMessageType.CSEAuthenticate;
import static com.io7m.certusine.etcd.internal.dto.CSEMessageType.CSEAuthenticateResponse;
import static com.io7m.certusine.etcd.internal.dto.CSEMessageType.CSEAuthenticateResponseHeader;
import static com.io7m.certusine.etcd.internal.dto.CSEMessageType.CSEError;
import static com.io7m.certusine.etcd.internal.dto.CSEMessageType.CSETransactionResponse;

/**
 * Messages for the etcd protocol.
 */

public final class CSEtcdMessages
{
  private final JsonMapper mapper;
  private final SimpleDeserializers serializers;

  /**
   * Messages for the etcd protocol.
   */

  public CSEtcdMessages()
  {
    this.serializers =
      DmJsonRestrictedDeserializers.builder()
        .allowClass(boolean.class)
        .allowClass(BigInteger.class)
        .allowClass(CEKV.class)
        .allowClass(CERequestPut.class)
        .allowClass(CSEAuthenticate.class)
        .allowClass(CSEAuthenticateResponse.class)
        .allowClass(CSEAuthenticateResponseHeader.class)
        .allowClass(CSEError.class)
        .allowClass(CSEMessageType.class)
        .allowClass(CSETransaction.class)
        .allowClass(CSETransactionResponse.class)
        .allowClass(String.class)
        .allowClass(URI.class)
        .allowClass(Void.class)
        .allowClassName(
          "java.util.List<com.io7m.certusine.etcd.internal.dto.CSEMessageType$CERequestPut>")
        .allowClassName("java.util.List<java.lang.Void>")
        .build();

    this.mapper =
      JsonMapper.builder()
        .enable(USE_BIG_INTEGER_FOR_INTS)
        .enable(ORDER_MAP_ENTRIES_BY_KEYS)
        .enable(SORT_PROPERTIES_ALPHABETICALLY)
        .build();

    final var simpleModule = new SimpleModule();
    simpleModule.setDeserializers(this.serializers);
    this.mapper.registerModule(simpleModule);
  }

  /**
   * Serialize a message.
   *
   * @param message The message
   *
   * @return The serialized message
   *
   * @throws JsonProcessingException On errors
   */

  public byte[] serialize(
    final CSEMessageType message)
    throws JsonProcessingException
  {
    return this.mapper.writeValueAsBytes(message);
  }

  /**
   * Deserialize a message.
   *
   * @param data The serialized message
   *
   * @return The message
   *
   * @throws JsonProcessingException On errors
   */

  public CSEMessageType deserialize(
    final byte[] data)
    throws IOException
  {
    return this.mapper.readValue(data, CSEMessageType.class);
  }
}
