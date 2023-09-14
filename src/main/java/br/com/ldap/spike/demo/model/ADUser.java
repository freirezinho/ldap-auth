package br.com.ldap.spike.demo.model;

import jakarta.annotation.Nullable;

public class ADUser {
    public String id;
    @Nullable
    public String name;
    @Nullable
    public String group;

    public ADUser(String id, @Nullable String name, @Nullable String group) {
        this.id = id;
        this.name = name;
        this.group = group;
    }
}
