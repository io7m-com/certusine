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

import com.io7m.anethum.api.ParseStatus;
import com.io7m.anethum.api.ParsingException;
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
import com.io7m.certusine.api.CSFaultInjectionConfiguration;
import com.io7m.certusine.api.CSOpenTelemetryConfiguration;
import com.io7m.certusine.api.CSOptions;
import com.io7m.certusine.vanilla.internal.jaxb.Accounts;
import com.io7m.certusine.vanilla.internal.jaxb.Certificate;
import com.io7m.certusine.vanilla.internal.jaxb.Certificates;
import com.io7m.certusine.vanilla.internal.jaxb.Configuration;
import com.io7m.certusine.vanilla.internal.jaxb.DNSConfigurators;
import com.io7m.certusine.vanilla.internal.jaxb.Domains;
import com.io7m.certusine.vanilla.internal.jaxb.FaultInjection;
import com.io7m.certusine.vanilla.internal.jaxb.Host;
import com.io7m.certusine.vanilla.internal.jaxb.OpenTelemetry;
import com.io7m.certusine.vanilla.internal.jaxb.OpenTelemetryProtocol;
import com.io7m.certusine.vanilla.internal.jaxb.Options;
import com.io7m.certusine.vanilla.internal.jaxb.Outputs;
import com.io7m.certusine.vanilla.internal.jaxb.Parameters;
import com.io7m.jlexing.core.LexicalPosition;
import com.io7m.jlexing.core.LexicalPositions;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.ValidationEventLocator;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.XMLConstants;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.SchemaFactory;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
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

import static com.io7m.anethum.api.ParseSeverity.PARSE_ERROR;
import static com.io7m.anethum.api.ParseSeverity.PARSE_WARNING;
import static com.io7m.certusine.api.CSOpenTelemetryConfiguration.CSLogs;
import static com.io7m.certusine.api.CSOpenTelemetryConfiguration.CSMetrics;
import static com.io7m.certusine.api.CSOpenTelemetryConfiguration.CSOTLPProtocol;
import static com.io7m.certusine.api.CSOpenTelemetryConfiguration.CSTraces;
import static jakarta.xml.bind.ValidationEvent.ERROR;
import static jakarta.xml.bind.ValidationEvent.FATAL_ERROR;
import static jakarta.xml.bind.ValidationEvent.WARNING;
import static java.lang.Boolean.FALSE;

/**
 * A certificate pipeline parser.
 */

public final class CSConfigurationParser
  implements CSConfigurationParserType
{
  private static final Logger LOG =
    LoggerFactory.getLogger(CSConfigurationParser.class);

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

    this.accounts = new HashMap<>();
    this.dns = new HashMap<>();
    this.domains = new HashMap<>();
    this.outputs = new HashMap<>();
    this.statusValues = new ArrayList<>();
  }

  @Override
  public void close()
    throws IOException
  {
    this.stream.close();
  }

  @Override
  public CSConfiguration execute()
    throws ParsingException
  {
    this.accounts.clear();
    this.dns.clear();
    this.domains.clear();
    this.outputs.clear();
    this.statusValues.clear();
    this.options = null;

    try {
      final var schemas =
        SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
      final var schema =
        schemas.newSchema(
          CSConfigurationParser.class.getResource(
            "/com/io7m/certusine/vanilla/internal/config-1.xsd")
        );

      final var context =
        JAXBContext.newInstance(
          "com.io7m.certusine.vanilla.internal.jaxb");
      final var unmarshaller =
        context.createUnmarshaller();

      unmarshaller.setEventHandler(event -> {
        final var locator = event.getLocator();
        switch (event.getSeverity()) {
          case WARNING -> {
            this.publishWarning(
              "warn-xml",
              locatorLexical(locator),
              event.getMessage()
            );
          }
          case ERROR, FATAL_ERROR -> {
            this.failed = true;
            this.publishError(
              "error-xml-validation",
              locatorLexical(locator),
              event.getMessage()
            );
          }
        }
        return true;
      });

      unmarshaller.setSchema(schema);

      final var streamSource =
        new StreamSource(this.stream, this.source.toString());

      final var rawConfiguration =
        (Configuration) unmarshaller.unmarshal(streamSource);

      if (this.failed) {
        throw new ParsingException(
          this.strings.format("parseFailed"),
          List.copyOf(this.statusValues)
        );
      }

      return this.processConfiguration(rawConfiguration);
    } catch (final JAXBException e) {
      LOG.debug("jaxb exception: ", e);

      this.publishError(
        createParseError(
          "error-jaxb",
          LexicalPositions.zero(),
          this.strings.format("parseFailed"))
      );
      throw new ParsingException(
        this.strings.format("parseFailed"),
        List.copyOf(this.statusValues)
      );
    } catch (final Exception e) {
      LOG.debug("exception: ", e);

      this.publishError(
        createParseError(
          "error-parse",
          LexicalPositions.zero(),
          this.strings.format("parseFailed"))
      );
      throw new ParsingException(
        this.strings.format("parseFailed"),
        List.copyOf(this.statusValues)
      );
    }
  }

  private static LexicalPosition<URI> locatorLexical(
    final ValidationEventLocator locator)
  {
    try {
      return LexicalPosition.of(
        locator.getLineNumber(),
        locator.getColumnNumber(),
        Optional.of(locator.getURL().toURI())
      );
    } catch (final URISyntaxException e) {
      throw new IllegalStateException(e);
    }
  }

  private CSConfiguration processConfiguration(
    final Configuration configuration)
    throws ParsingException
  {
    this.buildOptions(
      configuration.getOptions(),
      configuration.getOpenTelemetry(),
      configuration.getFaultInjection()
    );
    this.buildOutputs(configuration.getOutputs());
    this.buildDNSConfigurators(configuration.getDNSConfigurators());
    this.buildAccounts(configuration.getAccounts());
    this.buildDomains(configuration.getDomains());

    if (this.failed) {
      throw new ParsingException(
        this.strings.format("parseFailed"),
        List.copyOf(this.statusValues)
      );
    }

    return new CSConfiguration(
      this.options,
      this.domains
    );
  }

  private void buildDomains(
    final Domains domainsRaw)
  {
    for (final var domain : domainsRaw.getDomain()) {
      final var domainName =
        domain.getName();
      final var domainOutputs =
        new HashMap<String, CSCertificateOutputType>();

      final var outputReferences =
        domain.getOutputReferences();

      for (final var outputReference : outputReferences.getOutputReference()) {
        final var outputName =
          outputReference.getName();
        final var output =
          this.outputs.get(outputName);

        domainOutputs.put(outputName, output);
      }

      final var account =
        this.accounts.get(domain.getAccount());

      final var dnsConfigurator =
        this.dns.get(domain.getDNSConfigurator());

      final var certificates =
        this.buildCertificates(
          domainName,
          domain.getCertificates()
        );

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
      }
    }
  }

  private Map<String, CSCertificate> buildCertificates(
    final String domainName,
    final Certificates certificates)
  {
    final var results = new HashMap<String, CSCertificate>();

    for (final var certificate : certificates.getCertificate()) {
      try {
        final var name =
          certificate.getName();

        final var publicKey =
          this.loadPublicKey(
            LexicalPositions.zero(),
            this.baseDirectory.resolve(certificate.getPublicKeyPath())
          );
        final var privateKey =
          this.loadPrivateKey(
            LexicalPositions.zero(),
            this.baseDirectory.resolve(certificate.getPrivateKeyPath())
          );

        final var hostNames =
          certificate.getHosts()
            .getHost()
            .stream()
            .map(Host::getName)
            .toList();

        for (final var hostName : hostNames) {
          if (hostName.contains(domainName)) {
            this.publishWarning(
              "warn-host-contains-domain",
              LexicalPositions.zero(),
              this.strings.format(
                "warnHostContainsDomain",
                hostName,
                domainName)
            );
          }
        }

        final var newCertificate =
          new CSCertificate(
            this.parseCertificateName(certificate),
            new KeyPair(publicKey, privateKey),
            hostNames
          );

        results.put(name, newCertificate);
      } catch (final CSInternalParseException e) {
        // Ignore and continue
      }
    }

    return results;
  }

  private CSCertificateName parseCertificateName(
    final Certificate certificate)
    throws CSInternalParseException
  {
    final var name = certificate.getName();
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

  private void buildOptions(
    final Options optionsRaw,
    final OpenTelemetry openTelemetry,
    final FaultInjection faultInjection)
  {
    try {
      this.options = new CSOptions(
        this.baseDirectory.resolve(optionsRaw.getCertificateStore()),
        Duration.parse(optionsRaw.getDNSWaitTime().toString()),
        Duration.parse(optionsRaw.getCertificateExpirationThreshold().toString()),
        processOpenTelemetry(openTelemetry),
        processFaultInjection(faultInjection)
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

  private static CSFaultInjectionConfiguration processFaultInjection(
    final FaultInjection faultInjection)
  {
    if (faultInjection == null) {
      return CSFaultInjectionConfiguration.disabled();
    }

    final var failTasks =
      Optional.ofNullable(faultInjection.isFailTasks())
        .orElse(FALSE)
        .booleanValue();

    final var failDNS =
      Optional.ofNullable(faultInjection.isFailDNSChallenge())
        .orElse(FALSE)
        .booleanValue();

    final var failSigning =
      Optional.ofNullable(faultInjection.isFailSigningCertificates())
        .orElse(FALSE)
        .booleanValue();

    final var crashTasks =
      Optional.ofNullable(faultInjection.isCrashTasks())
        .orElse(FALSE)
        .booleanValue();

    final var crashDNS =
      Optional.ofNullable(faultInjection.isCrashDNSChallenge())
        .orElse(FALSE)
        .booleanValue();

    final var crashSigning =
      Optional.ofNullable(faultInjection.isCrashSigningCertificates())
        .orElse(FALSE)
        .booleanValue();

    return new CSFaultInjectionConfiguration(
      failTasks,
      failDNS,
      failSigning,
      crashTasks,
      crashDNS,
      crashSigning
    );
  }

  private void buildDNSConfigurators(
    final DNSConfigurators dnsConfigurators)
  {
    for (final var dnsConfigurator : dnsConfigurators.getDNSConfigurator()) {
      final var provider =
        this.dnsProviders.get(dnsConfigurator.getType());

      if (provider == null) {
        this.publishError(
          "error-unrecognized-provider",
          LexicalPositions.zero(),
          this.strings.format(
            "errorDNSProviderNonexistent",
            dnsConfigurator.getType(),
            this.dnsProviders.keySet())
        );
        continue;
      }

      final var parameters =
        this.toConfigurationParameters(dnsConfigurator.getParameters());

      final var dnsName = dnsConfigurator.getName();
      try {
        this.dns.put(dnsName, provider.create(parameters));
      } catch (final CSConfigurationException ex) {
        ex.errors().forEach(this::publishError);
      }
    }
  }

  private CSConfigurationParameters toConfigurationParameters(
    final Parameters parametersRaw)
  {
    final var stringParameters = new HashMap<String, String>();
    for (final var parameter : parametersRaw.getParameter()) {
      stringParameters.put(parameter.getName(), parameter.getValue());
    }

    return new CSConfigurationParameters(
      this.baseDirectory,
      LexicalPositions.zero(),
      Map.copyOf(stringParameters)
    );
  }

  private void buildOutputs(
    final Outputs outputsRaw)
  {
    for (final var output : outputsRaw.getOutput()) {
      final var provider =
        this.outputProviders.get(output.getType());

      if (provider == null) {
        this.publishError(
          "error-unrecognized-provider",
          LexicalPositions.zero(),
          this.strings.format(
            "errorOutputProviderNonexistent",
            output.getType(),
            this.outputProviders.keySet())
        );
        continue;
      }

      final var parameters =
        this.toConfigurationParameters(output.getParameters());

      final var outputName = output.getName();
      if (!this.outputs.containsKey(outputName)) {
        try {
          this.outputs.put(outputName, provider.create(outputName, parameters));
        } catch (final CSConfigurationException ex) {
          ex.errors().forEach(this::publishError);
        }
      }
    }
  }

  private void buildAccounts(
    final Accounts accountsRaw)
  {
    for (final var account : accountsRaw.getAccount()) {
      try {
        final var publicKey =
          this.loadPublicKey(
            LexicalPositions.zero(),
            this.baseDirectory.resolve(account.getPublicKeyPath())
          );
        final var privateKey =
          this.loadPrivateKey(
            LexicalPositions.zero(),
            this.baseDirectory.resolve(account.getPrivateKeyPath())
          );

        final CSAccount newAccount;
        try {
          newAccount = new CSAccount(
            new KeyPair(publicKey, privateKey),
            URI.create(account.getAcmeURI())
          );
        } catch (final IllegalArgumentException e) {
          this.publishError(
            "error-account-uri",
            LexicalPositions.zero(),
            this.strings.format("errorAccountURI", e.getMessage())
          );
          continue;
        }

        final var accountName = account.getName();
        this.accounts.put(accountName, newAccount);
      } catch (final CSInternalParseException e) {
        // Ignore and continue!
      }
    }
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
      ParseStatus.builder(errorCode, message)
        .withLexical(lex)
        .withSeverity(PARSE_WARNING)
        .build();

    this.statusValues.add(status);
    this.statusConsumer.accept(status);
  }

  private static ParseStatus createParseError(
    final String errorCode,
    final LexicalPosition<URI> lexical,
    final String message)
  {
    return ParseStatus.builder(errorCode, message)
      .withSeverity(PARSE_ERROR)
      .withLexical(lexical)
      .build();
  }

  private PrivateKey loadPrivateKey(
    final LexicalPosition<URI> lexical,
    final Path privateFile)
    throws CSInternalParseException
  {
    try (var reader = Files.newBufferedReader(privateFile)) {
      try (var parser = new PEMParser(reader)) {
        final var object = parser.readObject();
        if (object instanceof final PEMKeyPair keyPair) {
          return this.keyConverter.getPrivateKey(keyPair.getPrivateKeyInfo());
        }
        if (object instanceof final PrivateKeyInfo info) {
          return this.keyConverter.getPrivateKey(info);
        }

        throw this.publishError(
          "error-private-key-corrupt",
          lexical,
          this.strings.format("errorPrivateKeyCorrupt", privateFile)
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
        if (object instanceof final SubjectPublicKeyInfo info) {
          return this.keyConverter.getPublicKey(info);
        }
        if (object instanceof final X509CertificateHolder certificate) {
          return this.keyConverter.getPublicKey(certificate.getSubjectPublicKeyInfo());
        }

        throw this.publishError(
          "error-public-key-corrupt",
          lexical,
          this.strings.format("errorPublicKeyCorrupt", publicFile)
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

  private static Optional<CSOpenTelemetryConfiguration> processOpenTelemetry(
    final OpenTelemetry openTelemetry)
  {
    if (openTelemetry == null) {
      return Optional.empty();
    }

    final var metrics =
      Optional.ofNullable(openTelemetry.getMetrics())
        .map(m -> new CSMetrics(
          URI.create(m.getEndpoint()),
          processProtocol(m.getProtocol())
        ));

    final var traces =
      Optional.ofNullable(openTelemetry.getTraces())
        .map(m -> new CSTraces(
          URI.create(m.getEndpoint()),
          processProtocol(m.getProtocol())
        ));

    final var logs =
      Optional.ofNullable(openTelemetry.getLogs())
        .map(m -> new CSLogs(
          URI.create(m.getEndpoint()),
          processProtocol(m.getProtocol())
        ));

    return Optional.of(
      new CSOpenTelemetryConfiguration(
        openTelemetry.getLogicalServiceName(),
        logs,
        metrics,
        traces
      )
    );
  }

  private static CSOTLPProtocol processProtocol(
    final OpenTelemetryProtocol protocol)
  {
    return switch (protocol) {
      case GRPC -> CSOTLPProtocol.GRPC;
      case HTTP -> CSOTLPProtocol.HTTP;
    };
  }
}
