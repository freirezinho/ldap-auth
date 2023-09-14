package br.com.ldap.spike.demo.config;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.NamingException;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.authentication.LdapAuthenticator;
import org.springframework.security.ldap.authentication.PasswordComparisonAuthenticator;
import org.springframework.security.ldap.ppolicy.PasswordPolicyException;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationProvider;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class WebSecConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .requestMatchers("/protected/**")
                .fullyAuthenticated()
                .and()
                .formLogin()
                .and()
                .cors()
                .and()
                .csrf().disable();
        http.authenticationProvider(ldapAuthenticationProvider());
        return http.build();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("*"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    LdapAuthenticationProvider ldapAuthenticationProvider() {
        return new LdapAuthenticationProvider(authenticator());
    }

    @Bean
    BindAuthenticator authenticator() {
        FilterBasedLdapUserSearch search = new FilterBasedLdapUserSearch("ou=Users",
                "(cn={0})", contextSource());
        // PasswordComparisonAuthenticator authenticator = new
        // PasswordComparisonAuthenticator(contextSource());
        // authenticator.setUserSearch(search);
        // authenticator.setPasswordAttributeName("userpassword");
        // authenticator.setUsePasswordAttrCompare(true);
        BindAuthenticator authenticator = new BindAuthenticator(contextSource());
        authenticator.setUserSearch(search);
        return authenticator;
    }

    @Bean
    public DefaultSpringSecurityContextSource contextSource() {
        DefaultSpringSecurityContextSource dSctx = new DefaultSpringSecurityContextSource(
                "ldap://localhost:389/dc=example,dc=org");
        dSctx.setUserDn("cn=admin,dc=example,dc=org");
        dSctx.setPassword("admin");
        return dSctx;
    }
}

// modify UsernamePasswordAuthenticationFilter
// use ldap inside
// profit
// class JWTAuth extends LdapAuthenticationProvider {

// private LdapAuthenticator authenticator;

// private boolean hideUserNotFoundExceptions = true;

// private LdapAuthenticator getUsedAuthenticator() {
// return this.authenticator;
// }

// public JWTAuth(LdapAuthenticator authenticator) {
// super(authenticator);
// }

// @Override
// protected DirContextOperations
// doAuthentication(UsernamePasswordAuthenticationToken authentication) {
// try {
// return getUsedAuthenticator().authenticate(authentication);
// } catch (PasswordPolicyException ex) {
// // The only reason a ppolicy exception can occur during a bind is that the
// // account is locked.
// throw new LockedException(
// this.messages.getMessage(ex.getStatus().getErrorCode(),
// ex.getStatus().getDefaultMessage()));
// } catch (UsernameNotFoundException ex) {
// if (this.hideUserNotFoundExceptions) {
// throw new BadCredentialsException(
// this.messages.getMessage("LdapAuthenticationProvider.badCredentials", "Bad
// credentials"));
// }
// throw ex;
// } catch (NamingException ex) {
// throw new InternalAuthenticationServiceException(ex.getMessage(), ex);
// }
// }

// }
