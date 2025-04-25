package com.hospital.api_gateway.dto;

import lombok.Data;

@Data
public class LoginResponse {
    private String token;

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
}