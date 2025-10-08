package com.example.FinanceTracker.users.dto;

import com.example.FinanceTracker.users.User;
import lombok.Getter;
import lombok.Setter;

public class AuthResponse {

    @Setter

    private Long id;
    private String email;

    public AuthResponse(User user) {
        this.id = user.getId();
        this.email = user.getEmail();
    }
}
