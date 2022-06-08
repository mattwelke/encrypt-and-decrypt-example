package com.mattwelke;

import io.micronaut.context.annotation.ConfigurationProperties;

// Used https://guides.micronaut.io/latest/micronaut-configuration-gradle-java.html
// for reference to make this.
@ConfigurationProperties("encryption")
public class EncryptionConfiguration {

    private String password;

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
    
    private String salt;

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }
}
