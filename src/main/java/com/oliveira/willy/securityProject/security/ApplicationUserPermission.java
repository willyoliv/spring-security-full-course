package com.oliveira.willy.securityProject.security;

public enum ApplicationUserPermission {
    STUDENT_READ("stydent:read"),
    STUDENT_WRITE("student:write"),
    COURSE_READ("course:read"),
    COURSE_WRITE("course_write");

    private final String permission;

    ApplicationUserPermission(String permission) {
        this.permission = permission;
    }

    public String getPermission() {
        return permission;
    }
}
