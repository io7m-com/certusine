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


package com.io7m.certusine.vanilla.internal.store;

import com.io7m.certusine.api.CSConfiguration;
import com.io7m.certusine.api.CSConfigurationServiceType;
import com.io7m.certusine.certstore.api.CSCertificateStoreFactoryType;
import com.io7m.certusine.certstore.api.CSCertificateStoreType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Objects;
import java.util.concurrent.Flow;

/**
 * A certificate store service.
 */

public final class CSCertificateStoreService
  implements CSCertificateStoreServiceType, Flow.Subscriber<CSConfiguration>
{
  private static final Logger LOG =
    LoggerFactory.getLogger(CSCertificateStoreService.class);

  private final CSCertificateStoreFactoryType stores;
  private volatile CSCertificateStoreType store;
  private volatile Path storePath;
  private Flow.Subscription subscription;

  private CSCertificateStoreService(
    final CSCertificateStoreFactoryType inStores,
    final CSCertificateStoreType inStore,
    final Path path)
  {
    this.stores =
      Objects.requireNonNull(inStores, "stores");
    this.store =
      Objects.requireNonNull(inStore, "store");
    this.storePath =
      Objects.requireNonNull(path, "path");
  }

  /**
   * Open a certificate store service.
   *
   * @param configuration The configuration service
   * @param stores        The store factory
   *
   * @return A new service
   *
   * @throws IOException On errors
   */

  public static CSCertificateStoreServiceType store(
    final CSConfigurationServiceType configuration,
    final CSCertificateStoreFactoryType stores)
    throws IOException
  {
    final var path =
      configuration.configuration()
        .options()
        .certificateStore()
        .toAbsolutePath();

    final var store =
      stores.open(path);

    final var service =
      new CSCertificateStoreService(stores, store, path);

    configuration.events().subscribe(service);
    return service;
  }

  @Override
  public CSCertificateStoreType store()
  {
    return this.store;
  }

  @Override
  public String description()
  {
    return "Certificate store service";
  }

  @Override
  public void close()
    throws Exception
  {
    this.store.close();
    this.subscription.cancel();
  }

  @Override
  public void onSubscribe(
    final Flow.Subscription newSubscription)
  {
    this.subscription =
      Objects.requireNonNull(newSubscription, "subscription");

    this.subscription.request(1L);
  }

  @Override
  public void onNext(
    final CSConfiguration item)
  {
    this.reloadStore(item);
    this.subscription.request(1L);
  }

  private void reloadStore(
    final CSConfiguration item)
  {
    try {
      final var newPath =
        item.options()
          .certificateStore()
          .toAbsolutePath();

      if (newPath.equals(this.storePath)) {
        return;
      }

      final var newStore =
        this.stores.open(item.options().certificateStore());

      final var oldStore = this.store;
      this.store = newStore;
      this.storePath = newPath;
      oldStore.close();
    } catch (final IOException e) {
      LOG.error("failed to open new certificate store: ", e);
    }
  }

  @Override
  public void onError(
    final Throwable throwable)
  {

  }

  @Override
  public void onComplete()
  {

  }
}
