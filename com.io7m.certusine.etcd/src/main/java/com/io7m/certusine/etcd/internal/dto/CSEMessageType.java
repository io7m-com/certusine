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


package com.io7m.certusine.etcd.internal.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import java.math.BigInteger;
import java.util.List;

import static com.io7m.certusine.etcd.internal.dto.CSEMessageType.CEKV;
import static com.io7m.certusine.etcd.internal.dto.CSEMessageType.CERequestPut;
import static com.io7m.certusine.etcd.internal.dto.CSEMessageType.CSEAuthenticate;
import static com.io7m.certusine.etcd.internal.dto.CSEMessageType.CSEAuthenticateResponse;
import static com.io7m.certusine.etcd.internal.dto.CSEMessageType.CSEAuthenticateResponseHeader;
import static com.io7m.certusine.etcd.internal.dto.CSEMessageType.CSEError;
import static com.io7m.certusine.etcd.internal.dto.CSEMessageType.CSETransaction;
import static com.io7m.certusine.etcd.internal.dto.CSEMessageType.CSETransactionResponse;

// CHECKSTYLE:OFF

@JsonSubTypes(
  value = {
    @JsonSubTypes.Type(
      value = CSEAuthenticate.class,
      name = "CSEAuthenticate"),
    @JsonSubTypes.Type(
      value = CSEError.class,
      name = "CSEError"),
    @JsonSubTypes.Type(
      value = CSEAuthenticateResponse.class,
      name = "CSEAuthenticateResponse"),
    @JsonSubTypes.Type(
      value = CSEAuthenticateResponseHeader.class,
      name = "CSEAuthenticateResponseHeader"),
    @JsonSubTypes.Type(
      value = CEKV.class,
      name = "CEKV"),
    @JsonSubTypes.Type(
      value = CERequestPut.class,
      name = "CERequestPut"),
    @JsonSubTypes.Type(
      value = CSETransaction.class,
      name = "CSETransaction"),
    @JsonSubTypes.Type(
      value = CSETransactionResponse.class,
      name = "CSETransactionResponse")
  }
)
@JsonTypeInfo(use = JsonTypeInfo.Id.DEDUCTION, visible = false)
public sealed interface CSEMessageType
{
  @JsonSerialize
  @JsonDeserialize
  @JsonTypeName(value = "CSEAuthenticateResponseHeader")
  record CSEAuthenticateResponseHeader(
    @JsonProperty(value = "cluster_id", required = true)
    String clusterId,
    @JsonProperty(value = "member_id", required = true)
    String memberId,
    @JsonProperty(value = "revision", required = true)
    String revision,
    @JsonProperty(value = "raft_term", required = true)
    String raftTerm)
    implements CSEMessageType
  {

  }

  @JsonSerialize
  @JsonDeserialize
  @JsonTypeName(value = "CSEAuthenticateResponse")
  record CSEAuthenticateResponse(
    @JsonProperty(value = "header", required = true)
    CSEAuthenticateResponseHeader header,
    @JsonProperty(value = "token", required = true)
    String token)
    implements CSEMessageType
  {

  }

  @JsonSerialize
  @JsonDeserialize
  @JsonTypeName(value = "CSEAuthenticate")
  record CSEAuthenticate(
    @JsonProperty(value = "name", required = true)
    String name,
    @JsonProperty(value = "password", required = true)
    String password)
    implements CSEMessageType
  {

  }

  @JsonSerialize
  @JsonDeserialize
  @JsonTypeName(value = "CSEError")
  record CSEError(
    @JsonProperty(value = "error", required = true)
    String error,
    @JsonProperty(value = "code", required = true)
    BigInteger code,
    @JsonProperty(value = "message", required = true)
    String message)
    implements CSEMessageType
  {

  }

  @JsonSerialize
  @JsonDeserialize
  @JsonTypeName(value = "CEKV")
  record CEKV(
    @JsonProperty(value = "key", required = true)
    String key,
    @JsonProperty(value = "value", required = true)
    String value)
    implements CSEMessageType
  {

  }

  @JsonSerialize
  @JsonDeserialize
  @JsonTypeName(value = "CERequestPut")
  record CERequestPut(
    @JsonProperty(value = "requestPut", required = true)
    CEKV requestPut)
    implements CSEMessageType
  {

  }

  @JsonSerialize
  @JsonDeserialize
  @JsonTypeName(value = "CSETransaction")
  record CSETransaction(
    @JsonProperty(value = "compare", required = true)
    List<Void> compare,
    @JsonProperty(value = "success", required = true)
    List<CERequestPut> success)
    implements CSEMessageType
  {

  }

  @JsonSerialize
  @JsonDeserialize
  @JsonIgnoreProperties(value = "responses")
  @JsonTypeName(value = "CSETransactionResponse")
  record CSETransactionResponse(
    @JsonProperty(value = "header", required = true)
    CSEAuthenticateResponseHeader header,
    @JsonProperty(value = "succeeded", required = true)
    boolean succeeded)
    implements CSEMessageType
  {

  }
}
