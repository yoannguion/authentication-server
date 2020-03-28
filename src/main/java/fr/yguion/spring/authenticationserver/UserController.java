package fr.yguion.spring.authenticationserver;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import org.apache.catalina.realm.GenericPrincipal;

@RestController
public class UserController {

    @GetMapping("/user/me")
    public Principal user(Principal principal) {
        return principal;
    }

    /*    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();


        return new Principal() {

            @Override
            public String getName() {
                return "Andrew";
            }
        };
    }*/
}