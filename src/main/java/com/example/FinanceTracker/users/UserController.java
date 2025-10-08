package com.example.FinanceTracker.users;

import com.example.FinanceTracker.users.dto.AuthResponse;
import com.example.FinanceTracker.users.dto.SignupRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController()
@RequestMapping("/users")
public class UserController {
    private final UserService userService;

    @Autowired
    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/signup")
    public ResponseEntity<AuthResponse> createUser(@RequestBody @Valid SignupRequest signupRequest) {
        User savedUser = userService.create(signupRequest).getBody();
        assert savedUser != null;
        AuthResponse result = new AuthResponse(savedUser);
        return ResponseEntity.status(HttpStatus.CREATED).body(result);
    }

}
