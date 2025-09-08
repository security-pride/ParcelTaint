package com.cxxsheng.util;

import java.io.File;
import java.io.IOException;

public class FileWriter {
    private String filePath;
    private java.io.FileWriter writer;

    public FileWriter(String filePath) {
        this.filePath = filePath;
        createFile();
    }

    /**
     * Create an empty file (overwrites if exists)
     */
    private void createFile() {
        try {
            File file = new File(filePath);
            writer = new java.io.FileWriter(file, false);
        } catch (IOException e) {
            throw new RuntimeException("Failed to create file: " + filePath, e);
        }
    }

    /**
     * Append content to file
     * @param content content to append
     */
    public void writeLine(String content) {
        try {
            writer.write(content);
            writer.write(System.lineSeparator());
            writer.flush();
        } catch (IOException e) {
            throw new RuntimeException("Failed to append file: " + filePath, e);
        }
    }



    public void close() {
        try {
            if (writer != null) {
                writer.close();
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to close file: " + filePath, e);
        }
    }
}
