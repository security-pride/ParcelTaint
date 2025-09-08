package com.cxxsheng.permission;

public class Permission {
    private String name;
    private String label;
    private String description;
    private String protectionLevel;

    public Permission() {}

    // Getters and setters
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getLabel() { return label; }
    public void setLabel(String label) { this.label = label; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getProtectionLevel() { return protectionLevel; }
    public void setProtectionLevel(String protectionLevel) { this.protectionLevel = protectionLevel; }

    @Override
    public String toString() {
        return "Permission{" +
                "name='" + name + '\'' +
                ", label='" + label + '\'' +
                ", description='" + description + '\'' +
                ", protectionLevel='" + protectionLevel + '\'' +
                '}';
    }
}
