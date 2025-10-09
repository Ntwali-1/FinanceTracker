package com.example.FinanceTracker.users.dto;

import lombok.Setter;

public class JwtResponse {
    @Setter

    private String token;

    public JwtResponse(String token) {
        this.token = token;
    }
}
