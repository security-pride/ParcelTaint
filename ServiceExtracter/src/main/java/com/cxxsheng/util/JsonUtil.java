package com.cxxsheng.util;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.util.DefaultIndenter;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.File;
import java.io.IOException;

public class JsonUtil {
    private static final ObjectMapper mapper = new ObjectMapper();
    private static final DefaultPrettyPrinter printer = new DefaultPrettyPrinter();

    static {
        mapper.enable(SerializationFeature.INDENT_OUTPUT);
        mapper.configure(JsonParser.Feature.ALLOW_UNQUOTED_FIELD_NAMES, true);

        DefaultIndenter indenter = new DefaultIndenter("  ", "\n");
        printer.indentArraysWith(indenter);
        printer.indentObjectsWith(indenter);
    }

    public static void writeToJsonFile(Object data, String fileName) {
        try {
            File outputFile = new File(fileName);
            mapper.writer(printer).writeValue(outputFile, data);
            System.out.println("Analysis results written to: " + outputFile.getAbsolutePath());

            // System.out.println(formatJson(data));
        } catch (IOException e) {
            System.err.println("Error writing to file: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static String formatJson(Object obj) {
        try {
            return mapper.writer(printer).writeValueAsString(obj);
        } catch (JsonProcessingException e) {
            System.err.println("Error formatting JSON: " + e.getMessage());
            return null;
        }
    }
}