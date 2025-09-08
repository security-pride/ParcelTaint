package com.cxxsheng.util;


import com.cxxsheng.permission.Permission;
import com.cxxsheng.permission.PermissionParser;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class StringUtil {

    public static boolean listContains(List<String> hitStrings, List target) {
        for (Object o : target) {
            if (hitStrings.contains(o.toString())) {
                return true;
            }
        }
        return false;
    }

    public static boolean listContains(Set<String> hitStrings, List target) {
        for (Object o : target) {
            if (hitStrings.contains(o.toString())) {
                return true;
            }
        }
        return false;
    }

    public static Set<String> extractPermissions(String input) {
        Set<String> permissions = new HashSet<>();

        Pattern pattern = Pattern.compile("\"(android\\.permission\\.[A-Z_]+)\"");
        Matcher matcher = pattern.matcher(input);

        while (matcher.find()) {
            permissions.add(matcher.group(1));
        }

        return permissions;
    }



    public static String readStringFromFile(String filePath) throws IOException {
        return new String(Files.readAllBytes(Paths.get(filePath)), StandardCharsets.UTF_8);
    }

    public static String readStringFromResources(String resourcePath) throws IOException {
        try (InputStream inputStream = PermissionParser.class.getClassLoader().getResourceAsStream(resourcePath)) {
            if (inputStream == null) {
                throw new FileNotFoundException("Resource not found: " + resourcePath);
            }
            return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}