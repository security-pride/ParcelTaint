package com.cxxsheng.util;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;

public class Logger {
    private static PrintWriter writer;
    private static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    static {
        try {
            // true表示追加模式, false表示覆盖模式
            writer = new PrintWriter(new FileWriter("output.log", false));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void info(String message) {
        log("INFO", message);
    }

    public static void error(String message) {
        log("ERROR", message);
    }

    public static void debug(String message) {
        log("DEBUG", message);
    }

    private static void log(String level, String message) {
        String timeStamp = dateFormat.format(new Date());
        String logMessage = String.format("[%s] [%s] %s", timeStamp, level, message);

        writer.println(logMessage);
        writer.flush(); // 确保写入文件
    }

    // 在程序结束时关闭writer
    public static void close() {
        if (writer != null) {
            writer.close();
        }
    }
}