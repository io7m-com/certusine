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


package com.io7m.certusine.vanilla.internal;

import com.fasterxml.jackson.databind.DatabindException;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.module.SimpleDeserializers;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.io7m.anethum.common.ParseException;
import com.io7m.anethum.common.ParseStatus;
import com.io7m.certusine.api.CSAccount;
import com.io7m.certusine.api.CSCertificate;
import com.io7m.certusine.api.CSCertificateName;
import com.io7m.certusine.api.CSCertificateOutputProviderType;
import com.io7m.certusine.api.CSCertificateOutputType;
import com.io7m.certusine.api.CSConfiguration;
import com.io7m.certusine.api.CSConfigurationException;
import com.io7m.certusine.api.CSConfigurationParameters;
import com.io7m.certusine.api.CSConfigurationParserType;
import com.io7m.certusine.api.CSDNSConfiguratorProviderType;
import com.io7m.certusine.api.CSDNSConfiguratorType;
import com.io7m.certusine.api.CSDomain;
import com.io7m.certusine.api.CSOptions;
import com.io7m.certusine.vanilla.internal.dto.CS1Account;
import com.io7m.certusine.vanilla.internal.dto.CS1Certificate;
import com.io7m.certusine.vanilla.internal.dto.CS1Configuration;
import com.io7m.certusine.vanilla.internal.dto.CS1DNSConfigurator;
import com.io7m.certusine.vanilla.internal.dto.CS1Domain;
import com.io7m.certusine.vanilla.internal.dto.CS1Options;
import com.io7m.certusine.vanilla.internal.dto.CS1Output;
import com.io7m.certusine.vanilla.internal.dto.CS1Parameter;
import com.io7m.dixmont.core.DmJsonRestrictedDeserializers;
import com.io7m.jlexing.core.LexicalPosition;
import com.io7m.jlexing.core.LexicalPositions;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Duration;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;

import static com.fasterxml.jackson.databind.DeserializationFeature.USE_BIG_INTEGER_FOR_INTS;
import static com.fasterxml.jackson.databind.MapperFeature.SORT_PROPERTIES_ALPHABETICALLY;
import static com.fasterxml.jackson.databind.SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS;
import static com.io7m.anethum.common.ParseSeverity.PARSE_ERROR;
import static com.io7m.anethum.common.ParseSeverity.PARSE_WARNING;

/**
 * A certificate pipeline parser.
 */

public final class CSConfigurationParser
  implements CSConfigurationParserType
{
  private final CSStrings strings;
  private final Map<String, CSCertificateOutputProviderType> outputProviders;
  private final Map<String, CSDNSConfiguratorProviderType> dnsProviders;
  private final Path baseDirectory;
  private final InputStream stream;
  private final Consumer<ParseStatus> statusConsumer;
  private final ArrayList<ParseStatus> statusValues;
  private final HashMap<String, CSAccount> accounts;
  private final JcaPEMKeyConverter keyConverter;
  private final HashMap<String, CSCertificateOutputType> outputs;
  private final HashMap<String, CSDNSConfiguratorType> dns;
  private final HashMap<String, CSDomain> domains;
  private final SimpleDeserializers serializers;
  private final JsonMapper mapper;
  private final URI source;
  private boolean failed;
  private CSOptions options;

  /**
   * A certificate pipeline parser.
   *
   * @param inStrings         The string resources
   * @param inKeyConverter    The PEM key converter
   * @param inBaseDirectory   The base directory
   * @param inOutputProviders The supported output providers
   * @param inDNSProviders    The supported DNS providers
   * @param inStatusConsumer  A status message consumer
   * @param inSource          The input source
   * @param inStream          An input stream
   */

  public CSConfigurationParser(
    final CSStrings inStrings,
    final JcaPEMKeyConverter inKeyConverter,
    final Map<String, CSCertificateOutputProviderType> inOutputProviders,
    final Map<String, CSDNSConfiguratorProviderType> inDNSProviders,
    final Path inBaseDirectory,
    final InputStream inStream,
    final URI inSource,
    final Consumer<ParseStatus> inStatusConsumer)
  {
    this.strings =
      Objects.requireNonNull(inStrings, "strings");
    this.keyConverter =
      Objects.requireNonNull(inKeyConverter, "keyConverter");
    this.outputProviders =
      Objects.requireNonNull(inOutputProviders, "outputProviders");
    this.dnsProviders =
      Objects.requireNonNull(inDNSProviders, "inDNSProviders");
    this.baseDirectory =
      Objects.requireNonNull(inBaseDirectory, "baseDirectory");
    this.stream =
      Objects.requireNonNull(inStream, "stream");
    this.source =
      Objects.requireNonNull(inSource, "source");
    this.statusConsumer =
      Objects.requireNonNull(inStatusConsumer, "statusConsumer");

    this.serializers =
      DmJsonRestrictedDeserializers.builder()
        .allowClass(CS1Account.class)
        .allowClass(CS1Certificate.class)
        .allowClass(CS1Configuration.class)
        .allowClass(CS1DNSConfigurator.class)
        .allowClass(CS1Domain.class)
        .allowClass(CS1Output.class)
        .allowClass(CS1Parameter.class)
        .allowClass(CS1Options.class)
        .allowClass(String.class)
        .allowClass(URI.class)
        .allowClassName(
          "java.util.List<com.io7m.certusine.vanilla.internal.dto.CS1Account>")
        .allowClassName(
          "java.util.List<com.io7m.certusine.vanilla.internal.dto.CS1Certificate>")
        .allowClassName(
          "java.util.List<com.io7m.certusine.vanilla.internal.dto.CS1DNSConfigurator>")
        .allowClassName(
          "java.util.List<com.io7m.certusine.vanilla.internal.dto.CS1Domain>")
        .allowClassName(
          "java.util.List<com.io7m.certusine.vanilla.internal.dto.CS1Output>")
        .allowClassName(
          "java.util.List<com.io7m.certusine.vanilla.internal.dto.CS1Parameter>")
        .allowClassName("java.util.List<java.lang.String>")
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

    this.accounts = new HashMap<>();
    this.dns = new HashMap<>();
    this.domains = new HashMap<>();
    this.outputs = new HashMap<>();
    this.statusValues = new ArrayList<>();
  }

  private static ParseStatus createParseError(
    final String errorCode,
    final LexicalPosition<URI> lexical,
    final String message)
  {
    return ParseStatus.builder()
      .setSeverity(PARSE_ERROR)
      .setErrorCode(errorCode)
      .setLexical(lexical)
      .setMessage(message)
      .build();
  }

  @Override
  public void close()
    throws IOException
  {
    this.stream.close();
  }

  @Override
  public CSConfiguration execute()
    throws ParseException
  {
    this.accounts.clear();
    this.dns.clear();
    this.domains.clear();
    this.outputs.clear();
    this.statusValues.clear();
    this.options = null;

    final CS1Configuration configuration;
    try {
      configuration =
        this.mapper.readValue(this.stream, CS1Configuration.class);
    } catch (final DatabindException e) {
      this.publishError(
        "error-json",
        LexicalPosition.of(
          e.getLocation().getLineNr(),
          e.getLocation().getColumnNr(),
          Optional.of(this.source)
        ),
        e.getMessage()
      );
      throw new ParseException(
        this.strings.format("parseFailed"),
        List.copyOf(this.statusValues)
      );
    } catch (final IOException e) {
      this.publishError(
        "error-io",
        LexicalPositions.zero(),
        e.getMessage()
      );
      throw new ParseException(
        this.strings.format("parseFailed"),
        List.copyOf(this.statusValues)
      );
    }

    this.buildOptions(configuration);
    this.buildOutputs(configuration);
    this.buildDNSConfigurators(configuration);
    this.buildAccounts(configuration);
    this.buildDomains(configuration);

    if (this.failed) {
      throw new ParseException(
        this.strings.format("parseFailed"),
        List.copyOf(this.statusValues)
      );
    }

    return new CSConfiguration(
      this.options,
      this.domains
    );
  }

  private void buildOptions(
    final CS1Configuration configuration)
  {
    try {
      final var existingOptions =
        configuration.options();
      this.options = new CSOptions(
        this.baseDirectory.resolve(existingOptions.certificateStore()),
        Duration.parse(existingOptions.dnsWaitTime()),
        Duration.parse(existingOptions.certificateExpirationThreshold())
      );
    } catch (final DateTimeParseException e) {
      this.publishError(
        "error-duration",
        LexicalPositions.zero(),
        this.strings.format(
          "errorDuration",
          e.getMessage(),
          e.getParsedString()
        )
      );
    }
  }

  private void buildDomains(
    final CS1Configuration configuration)
  {
    for (final var domain : configuration.domains()) {
      final var domainName =
        domain.name();

      final var domainOutputs = new HashMap<String, CSCertificateOutputType>();
      for (final var outputName : domain.outputs()) {
        final var output = this.outputs.get(outputName);
        if (output == null) {
          this.publishError(
            "error-domain-output-nonexistent",
            LexicalPositions.zero(),
            this.strings.format(
              "errorDomainOutputNonexistent",
              domainName,
              outputName,
              this.outputs.keySet()
            )
          );
          continue;
        }
        domainOutputs.put(outputName, output);
      }

      final var account =
        this.accounts.get(domain.account());

      if (account == null) {
        this.publishError(
          "error-domain-account-nonexistent",
          LexicalPositions.zero(),
          this.strings.format(
            "errorDomainAccountNonexistent",
            domainName,
            domain.account()
          )
        );
        continue;
      }

      final var dnsConfigurator =
        this.dns.get(domain.dnsConfigurator());

      if (dnsConfigurator == null) {
        this.publishError(
          "error-domain-dnsconfigurator-nonexistent",
          LexicalPositions.zero(),
          this.strings.format(
            "errorDomainDNSConfiguratorNonexistent",
            domainName,
            domain.dnsConfigurator(),
            this.dns.keySet()
          )
        );
        continue;
      }

      final var certificates =
        this.buildCertificates(domainName, domain.certificates());

      final var newDomain =
        new CSDomain(
          account,
          domainName,
          certificates,
          dnsConfigurator,
          domainOutputs
        );

      if (!this.domains.containsKey(domainName)) {
        this.domains.put(domainName, newDomain);
        continue;
      }

      this.publishError(
        "error-domain-duplicate",
        LexicalPositions.zero(),
        this.strings.format("errorDomainDuplicate", domainName)
      );
    }
  }

  private Map<String, CSCertificate> buildCertificates(
    final String domainName,
    final List<CS1Certificate> certificates)
  {
    final var results = new HashMap<String, CSCertificate>();

    for (final var certificate : certificates) {
      try {
        final var name =
          certificate.name();

        final var publicKey =
          this.loadPublicKey(
            LexicalPositions.zero(),
            this.baseDirectory.resolve(certificate.publicKeyPath())
          );
        final var privateKey =
          this.loadPrivateKey(
            LexicalPositions.zero(),
            this.baseDirectory.resolve(certificate.privateKeyPath())
          );

        final var hostNames =
          certificate.hosts();

        for (final var hostName : hostNames) {
          if (hostName.contains(domainName)) {
            this.publishWarning(
              "warn-host-contains-domain",
              LexicalPositions.zero(),
              this.strings.format(
                "warnHostContainsDomain",
                name,
                domainName)
            );
          }
        }

        final var newCertificate =
          new CSCertificate(
            this.parseCertificateName(certificate),
            new KeyPair(publicKey, privateKey),
            certificate.hosts()
          );

        if (results.containsKey(name)) {
          this.publishError(
            "error-domain-certificate-duplicate",
            LexicalPositions.zero(),
            this.strings.format(
              "errorDomainCertificateDuplicate",
              domainName,
              name)
          );
          continue;
        }
        results.put(name, newCertificate);
      } catch (final CSInternalParseException e) {
        // Ignore and continue
      }
    }

    return results;
  }

  private CSCertificateName parseCertificateName(
    final CS1Certificate certificate)
    throws CSInternalParseException
  {
    final var name = certificate.name();
    try {
      return new CSCertificateName(name);
    } catch (final Exception e) {
      throw this.publishError(
        "error-certificate-name-invalid",
        LexicalPositions.zero(),
        this.strings.format("errorCertificateName", name, e.getMessage())
      );
    }
  }

  private void buildAccounts(
    final CS1Configuration configuration)
  {
    for (final var account : configuration.accounts()) {
      try {
        final var publicKey =
          this.loadPublicKey(
            LexicalPositions.zero(),
            this.baseDirectory.resolve(account.publicKeyPath())
          );
        final var privateKey =
          this.loadPrivateKey(
            LexicalPositions.zero(),
            this.baseDirectory.resolve(account.privateKeyPath())
          );

        final CSAccount newAccount;
        try {
          newAccount = new CSAccount(
            new KeyPair(publicKey, privateKey),
            account.acmeURI()
          );
        } catch (final IllegalArgumentException e) {
          this.publishError(
            "error-account-uri",
            LexicalPositions.zero(),
            this.strings.format("errorAccountURI", e.getMessage())
          );
          continue;
        }

        final var accountName = account.name();
        if (!this.accounts.containsKey(accountName)) {
          this.accounts.put(accountName, newAccount);
          continue;
        }

        this.publishError(
          "error-account-duplicate",
          LexicalPositions.zero(),
          this.strings.format("errorAccountDuplicate", accountName)
        );
      } catch (final CSInternalParseException e) {
        // Ignore and continue!
      }
    }
  }

  private void buildDNSConfigurators(
    final CS1Configuration configuration)
  {
    for (final var dnsConfigurator : configuration.dnsConfigurators()) {
      final var provider =
        this.dnsProviders.get(dnsConfigurator.type());

      if (provider == null) {
        this.publishError(
          "error-dns-provider-nonexistent",
          LexicalPositions.zero(),
          this.strings.format(
            "errorDNSProviderNonexistent",
            dnsConfigurator.type(),
            this.dnsProviders.keySet())
        );
        continue;
      }

      final var parameters =
        this.toConfigurationParameters(dnsConfigurator.parameters());

      final var dnsName = dnsConfigurator.name();
      if (!this.dns.containsKey(dnsName)) {
        try {
          this.dns.put(dnsName, provider.create(parameters));
        } catch (final CSConfigurationException ex) {
          ex.errors().forEach(this::publishError);
        }
        continue;
      }

      this.publishError(
        "error-dns-duplicate",
        LexicalPositions.zero(),
        this.strings.format("errorDNSDuplicate", dnsName)
      );
    }
  }

  private void buildOutputs(
    final CS1Configuration configuration)
  {
    for (final var output : configuration.outputs()) {
      final var provider =
        this.outputProviders.get(output.type());

      if (provider == null) {
        this.publishError(
          "error-output-provider-nonexistent",
          LexicalPositions.zero(),
          this.strings.format(
            "errorOutputProviderNonexistent",
            output.type(),
            this.outputProviders.keySet())
        );
        continue;
      }

      final var parameters =
        this.toConfigurationParameters(output.parameters());

      final var outputName = output.name();
      if (!this.outputs.containsKey(outputName)) {
        try {
          this.outputs.put(outputName, provider.create(outputName, parameters));
        } catch (final CSConfigurationException ex) {
          ex.errors().forEach(this::publishError);
        }
        continue;
      }

      this.publishError(
        "error-output-duplicate",
        LexicalPositions.zero(),
        this.strings.format("errorOutputDuplicate", outputName)
      );
    }
  }

  private CSConfigurationParameters toConfigurationParameters(
    final List<CS1Parameter> parameters)
  {
    final var stringParameters = new HashMap<String, String>();
    for (final var parameter : parameters) {
      if (stringParameters.containsKey(parameter.name())) {
        this.publishError(
          "error-parameter-duplicate",
          LexicalPositions.zero(),
          this.strings.format(
            "errorParameterDuplicate",
            parameter.name())
        );
        continue;
      }
      stringParameters.put(parameter.name(), parameter.value());
    }

    return new CSConfigurationParameters(
      this.baseDirectory,
      LexicalPositions.zero(),
      Map.copyOf(stringParameters)
    );
  }

  private void publishError(
    final ParseStatus status)
  {
    if (status.severity() == PARSE_ERROR) {
      this.failed = true;
    }

    this.statusValues.add(status);
    this.statusConsumer.accept(status);
  }

  private PrivateKey loadPrivateKey(
    final LexicalPosition<URI> lexical,
    final Path privateFile)
    throws CSInternalParseException
  {
    try (var reader = Files.newBufferedReader(privateFile)) {
      try (var parser = new PEMParser(reader)) {
        final var object = parser.readObject();
        if (object instanceof PEMKeyPair keyPair) {
          return this.keyConverter.getPrivateKey(keyPair.getPrivateKeyInfo());
        }
        if (object instanceof PrivateKeyInfo info) {
          return this.keyConverter.getPrivateKey(info);
        }

        throw this.publishError(
          "error-private-key-corrupt",
          lexical,
          this.strings.format("errorPrivateKeyCorrupt", object)
        );
      }
    } catch (final IOException e) {
      throw this.publishError(
        "error-io-file",
        lexical,
        this.strings.format(
          "errorIOFile",
          privateFile,
          e.getClass().getSimpleName())
      );
    }
  }

  private PublicKey loadPublicKey(
    final LexicalPosition<URI> lexical,
    final Path publicFile)
    throws CSInternalParseException
  {
    try (var reader = Files.newBufferedReader(publicFile)) {
      try (var parser = new PEMParser(reader)) {
        final var object = parser.readObject();
        if (object instanceof SubjectPublicKeyInfo info) {
          return this.keyConverter.getPublicKey(info);
        }
        if (object instanceof X509CertificateHolder certificate) {
          return this.keyConverter.getPublicKey(certificate.getSubjectPublicKeyInfo());
        }

        throw this.publishError(
          "error-public-key-corrupt",
          lexical,
          this.strings.format("errorPublicKeyCorrupt", object)
        );
      }
    } catch (final IOException e) {
      throw this.publishError(
        "error-io-file",
        lexical,
        this.strings.format(
          "errorIOFile",
          publicFile,
          e.getClass().getSimpleName())
      );
    }
  }

  private CSInternalParseException publishError(
    final String errorCode,
    final LexicalPosition<URI> lex,
    final String message)
  {
    this.publishError(createParseError(errorCode, lex, message));
    return new CSInternalParseException();
  }

  private void publishWarning(
    final String errorCode,
    final LexicalPosition<URI> lex,
    final String message)
  {
    final var status =
      ParseStatus.builder()
        .setErrorCode(errorCode)
        .setLexical(lex)
        .setSeverity(PARSE_WARNING)
        .setMessage(message)
        .build();

    this.statusValues.add(status);
    this.statusConsumer.accept(status);
  }
}
