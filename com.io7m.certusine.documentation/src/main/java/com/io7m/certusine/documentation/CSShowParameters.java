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

import com.beust.jcommander.Parameter;
import com.io7m.certusine.cmdline.internal.CSCheckConfiguration;
import com.io7m.certusine.cmdline.internal.CSGenerateKeyPair;
import com.io7m.certusine.cmdline.internal.CSLooseleafDownload;
import com.io7m.certusine.cmdline.internal.CSRenew;
import com.io7m.certusine.cmdline.internal.CSShowCertificateOutputs;
import com.io7m.certusine.cmdline.internal.CSShowDNSConfigurators;
import com.io7m.certusine.cmdline.internal.CSVersion;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.TRUNCATE_EXISTING;
import static java.nio.file.StandardOpenOption.WRITE;

/**
 * Generate example text.
 */

public final class CSShowParameters
{
  private static final String STRUCTURAL_8_0 = "urn:com.io7m.structural:8:0";

  private CSShowParameters()
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
    final var classes = List.of(
      CSCheckConfiguration.class,
      CSGenerateKeyPair.class,
      CSRenew.class,
      CSShowCertificateOutputs.class,
      CSShowDNSConfigurators.class,
      CSVersion.class,
      CSLooseleafDownload.class
    );

    for (final var clazz : classes) {
      final var path = Paths.get(clazz.getSimpleName() + ".xml");
      try (var output =
             Files.newOutputStream(path, WRITE, CREATE, TRUNCATE_EXISTING)) {
        toStructural(clazz, output);
        output.flush();
      }
    }
  }

  private static void toStructural(
    final Class<?> clazz,
    final OutputStream output)
    throws Exception
  {
    final var classes = new HashSet<Class<?>>();
    var clazzNow = clazz;
    while (!Objects.equals(clazzNow, Object.class)) {
      classes.add(clazzNow);
      clazzNow = clazzNow.getSuperclass();
    }

    final var parameters =
      classes.stream()
        .flatMap(CSShowParameters::parametersOfClass)
        .collect(Collectors.toList());

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

    for (final var p : parameters) {
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

      final var nameTerm = document.createElementNS(STRUCTURAL_8_0, "Term");
      nameTerm.setAttribute("type", "parameter");
      nameCell.appendChild(nameTerm);
      nameTerm.setTextContent(
        String.join(",", p.annotation.names())
      );

      final var typeTerm = document.createElementNS(STRUCTURAL_8_0, "Term");
      typeTerm.setAttribute("type", "constant");
      typeTerm.setTextContent(p.field.getType().getSimpleName());
      typeCell.appendChild(typeTerm);

      requiredCell.setTextContent(String.valueOf(p.annotation.required()));
      descriptionCell.setTextContent(p.annotation.description());
    }

    final var transformers = TransformerFactory.newInstance();
    final var transformer = transformers.newTransformer();
    transformer.setOutputProperty(OutputKeys.INDENT, "yes");

    final var source = new DOMSource(document);
    final var result = new StreamResult(output);
    transformer.transform(source, result);
  }

  record AnnotatedField(
    Parameter annotation,
    Field field)
  {

  }

  private static Stream<AnnotatedField> parametersOfClass(
    final Class<?> c)
  {
    return Stream.of(c.getDeclaredFields())
      .filter(f -> f.isAnnotationPresent(Parameter.class))
      .map(f -> new AnnotatedField(f.getAnnotation(Parameter.class), f));
  }
}
