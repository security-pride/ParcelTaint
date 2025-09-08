package com.cxxsheng.permission;

import com.cxxsheng.util.StringUtil;
import org.w3c.dom.*;
import javax.xml.parsers.*;
import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class PermissionParser {

    private final String filePath;
    private List<Permission> permisionList;

    public List<Permission> parsePermissions(String xmlContent) {
        List<Permission> permissions = new ArrayList<>();
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new ByteArrayInputStream(xmlContent.getBytes("UTF-8")));

            // 获取所有permission元素
            NodeList permissionNodes = doc.getElementsByTagName("permission");

            // 遍历所有permission节点
            for (int i = 0; i < permissionNodes.getLength(); i++) {
                Node permissionNode = permissionNodes.item(i);
                if (permissionNode.getNodeType() == Node.ELEMENT_NODE) {
                    Element permissionElement = (Element) permissionNode;
                    Permission permission = new Permission();

                    // 解析各个属性
                    permission.setName(permissionElement.getAttribute("android:name"));
                    permission.setLabel(permissionElement.getAttribute("android:label"));
                    permission.setDescription(permissionElement.getAttribute("android:description"));
                    permission.setProtectionLevel(permissionElement.getAttribute("android:protectionLevel"));

                    permissions.add(permission);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return permissions;
    }



    public PermissionParser(String filePath) {
        this.filePath = filePath;
    }

    public void parse() throws IOException {
        String str = StringUtil.readStringFromResources(this.filePath);
        this.permisionList = parsePermissions(str);
    }

    public List<Permission> getPermisionList() {
        return permisionList;
    }

    public boolean contains(String permissionName){
        for (Permission permission : permisionList) {
            if(permission.getName().equals(permissionName)){
                return true;
            }
        }
        return false;
    }

    public boolean isSystemPermission(String permissionName){
        for (Permission permission : permisionList) {
            if (permission.getName().equals(permissionName)){
                if (permission.getProtectionLevel().contains("normal"))
                    return false;
                else
                    return true;
            }
        }
        throw new RuntimeException("unkown permission: " + permissionName);
    }
}
