package com.yumyapps.jwt.listener;

import com.yumyapps.jwt.security.UserPrincipal;
import com.yumyapps.jwt.service.LoginAttemptService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationSuccessListener {

    private final LoginAttemptService loginAttemptService;
    @Autowired
    public AuthenticationSuccessListener(LoginAttemptService loginAttemptService) {
        this.loginAttemptService = loginAttemptService;
    }

    @EventListener
    public void onAuthenticationSuccessListener(AuthenticationSuccessEvent event) {
        Object principal = event.getAuthentication().getPrincipal();
        if (principal instanceof UserPrincipal) {
            var user = (UserPrincipal) event.getAuthentication().getPrincipal();
            loginAttemptService.activeUserFromLoginAttemptCache(user.getUsername());
        }

    }

}


