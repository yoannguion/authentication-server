package fr.yguion.spring.authenticationserver;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Map;

@RestController
public class UserController {

   /* @GetMapping("/user/me")
    public Principal user(Principal principal) {
        return principal;
    }*/


    @GetMapping("/user/me")
    public ResponseEntity<UserDto> me() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String principal = (String) authentication.getPrincipal();
        Map<String, Object> additionalInfo = getAdditionalInfo(authentication);
        int userId = (int) additionalInfo.get("user_id");
        return ResponseEntity.ok(new UserDto(principal, userId));
    }

    private Map<String, Object> getAdditionalInfo(Authentication authentication) {
        OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) authentication.getDetails();
        return (Map<String, Object>) details.getDecodedDetails();
    }

    private class UserDto {
        private String username;
        private int userId;

        UserDto(String username, int userId) {
            this.username = username;
            this.userId = userId;
        }

        public String getUsername() {
            return username;
        }

        public int getUserId() {
            return userId;
        }
    }

}