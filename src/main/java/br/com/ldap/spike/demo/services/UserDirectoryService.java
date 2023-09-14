package br.com.ldap.spike.demo.services;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import javax.naming.NameClassPair;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapEntryIdentification;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.NameClassPairCallbackHandler;
import org.springframework.ldap.filter.AndFilter;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.stereotype.Service;

import br.com.ldap.spike.demo.model.ADUser;
import br.com.ldap.spike.demo.util.JwtHandler;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserDirectoryService {
    private final LdapTemplate ldap;
    private Logger logger = LoggerFactory.getLogger(UserDirectoryService.class);

    @Autowired
    private JwtHandler jwt;

    private ADUser queryWithAttributeMapper(String userId) {
        String filter = "uid=" + userId;
        List<ADUser> usersFound = ldap.search("ou=Users", filter, (AttributesMapper<ADUser>) attributes -> {
            String id = attributes.get("uid").get().toString();
            String cn = attributes.get("cn").get().toString();
            String name = attributes.get("displayname").get().toString();
            String group = attributes.get("objectClass").get().toString();
            // List<String> emails = attributes.get("mail").all().toList();
            // List<String> emails =
            // getMultiValuedAttributesWithDefaultIncrementAttributesMapper("cn=" + cn +
            // ",ou=Users", "mail");
            return new ADUser(id, name, group);
        });
        return !usersFound.isEmpty() ? usersFound.get(0) : null;
    }

    public String getUser(String id) {
        ADUser user = queryWithAttributeMapper(id);
        return user.name;
    }

    public String getUserGroup(String id) {
        ADUser user = queryWithAttributeMapper(id);
        return user.group;
    }

    public String authUser(String username, String password) {
        logger.info(username);
        AtomicReference<String> data = new AtomicReference<>();
        String JSONwebToken = "";

        AndFilter filter = new AndFilter();
        filter.and(new EqualsFilter("cn", username));
        ldap.authenticate("ou=Users", filter.toString(), password, (DirContext ctx, LdapEntryIdentification ldap) -> {
            logger.info(ldap.getAbsoluteName().toString());
            data.set(ldap.getRelativeName().toString());
        });

        if (!data.get().isEmpty()) {
            JSONwebToken = jwt.generateToken(data.get());
        }

        return JSONwebToken.isEmpty() ? "NOOK" : JSONwebToken;
    }

    public String getPermissionsFromToken(String token) {
        String audience = jwt.getClaimFromToken(token, claims -> claims.get("ou", String.class));
        return audience;
    }
}