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

package com.io7m.certusine.documentation;

import com.io7m.certusine.api.CSCertificateOutputProviderType;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ServiceLoader;

import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.TRUNCATE_EXISTING;
import static java.nio.file.StandardOpenOption.WRITE;

/**
 * Generate example text.
 */

public final class CSShowCertificateOutputParameters
{
  private static final String STRUCTURAL_8_0 = "urn:com.io7m.structural:8:0";

  private CSShowCertificateOutputParameters()
  {

  }

  /**
   * Command-line entry point.
   *
   * @param args The arguments
   *
   * @throws Exception On errors
   */

  public static void main(
    final String[] args)
    throws Exception
  {
    ServiceLoader.load(CSCertificateOutputProviderType.class)
      .forEach(provider -> {
        try {
          writeProvider(provider);
        } catch (final Exception e) {
          throw new IllegalStateException(e);
        }
      });
  }

  private static void writeProvider(
    final CSCertificateOutputProviderType provider)
    throws Exception
  {
    final var documents =
      DocumentBuilderFactory.newDefaultInstance();

    documents.setNamespaceAware(true);

    final var documentBuilder =
      documents.newDocumentBuilder();
    final var document =
      documentBuilder.newDocument();
    final var table =
      document.createElementNS(STRUCTURAL_8_0, "Table");

    table.setAttribute("type", "genericTable");

    document.appendChild(table);

    final var columns =
      document.createElementNS(STRUCTURAL_8_0, "Columns");

    table.appendChild(columns);

    final var column0 = document.createElementNS(STRUCTURAL_8_0, "Column");
    column0.setTextContent("Parameter");
    final var column1 = document.createElementNS(STRUCTURAL_8_0, "Column");
    column1.setTextContent("Type");
    final var column2 = document.createElementNS(STRUCTURAL_8_0, "Column");
    column2.setTextContent("Required");
    final var column3 = document.createElementNS(STRUCTURAL_8_0, "Column");
    column3.setTextContent("Description");

    columns.appendChild(column0);
    columns.appendChild(column1);
    columns.appendChild(column2);
    columns.appendChild(column3);

    for (final var e : provider.parameters().entrySet()) {
      final var name = e.getKey();
      final var param = e.getValue();

      final var row = document.createElementNS(STRUCTURAL_8_0, "Row");
      table.appendChild(row);

      final var nameCell =
        document.createElementNS(STRUCTURAL_8_0, "Cell");
      final var typeCell =
        document.createElementNS(STRUCTURAL_8_0, "Cell");
      final var requiredCell =
        document.createElementNS(STRUCTURAL_8_0, "Cell");
      final var descriptionCell =
        document.createElementNS(STRUCTURAL_8_0, "Cell");

      row.appendChild(nameCell);
      row.appendChild(typeCell);
      row.appendChild(requiredCell);
      row.appendChild(descriptionCell);

      final var nameTerm =
        document.createElementNS(STRUCTURAL_8_0, "Term");
      nameTerm.setAttribute("type", "parameter");
      nameCell.appendChild(nameTerm);
      nameTerm.setTextContent(param.name());

      final var typeTerm =
        document.createElementNS(STRUCTURAL_8_0, "Term");
      typeTerm.setAttribute("type", "constant");
      typeTerm.setTextContent(param.format());
      typeCell.appendChild(typeTerm);

      requiredCell.setTextContent(String.valueOf(param.required()));
      descriptionCell.setTextContent(param.description());
    }

    final var transformers = TransformerFactory.newInstance();
    final var transformer = transformers.newTransformer();
    transformer.setOutputProperty(OutputKeys.INDENT, "yes");

    final var path = Paths.get("output-" + provider.name() + "-parameters.xml");
    try (var output =
           Files.newOutputStream(path, WRITE, CREATE, TRUNCATE_EXISTING)) {
      final var source = new DOMSource(document);
      final var result = new StreamResult(output);
      transformer.transform(source, result);
      output.flush();
    }
  }
}
