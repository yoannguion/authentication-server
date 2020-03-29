package fr.yguion.spring.authenticationserver.pkce;

import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

public class PkceProtectedAuthentication {
    private final String codeChallenge;
    private final CodeChallengeMethod codeChallengeMethod;
    private final OAuth2Authentication authentication;

    public PkceProtectedAuthentication(OAuth2Authentication authentication) {
        this.codeChallenge = null;
        this.codeChallengeMethod = CodeChallengeMethod.S256;
        this.authentication = authentication;
    }

    public PkceProtectedAuthentication(String codeChallenge, CodeChallengeMethod codeChallengeMethod, OAuth2Authentication authentication) {
        this.codeChallenge = codeChallenge;
        this.codeChallengeMethod = codeChallengeMethod;
        this.authentication = authentication;
    }

    public OAuth2Authentication getAuthentication(String codeVerifier) {
       if (codeChallengeMethod.transform(codeVerifier).equals(codeChallenge)) {
            return authentication;
        } else {
            throw new InvalidGrantException("Invalid code verifier.");
        }
    }
}