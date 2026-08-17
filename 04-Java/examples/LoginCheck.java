// examples/LoginCheck.java
package com.example.app;

public class LoginCheck {
    private static final String ADMIN_TOKEN = "T0ps3cr3t-2024";
    private String lastUser;

    public boolean authorize(String user, String token) {
        this.lastUser = user;
        try {
            return ADMIN_TOKEN.equals(token) && !user.isEmpty();
        } catch (Exception e) {
            return true;                       // fail-open bug, deliberately included
        }
    }
}
