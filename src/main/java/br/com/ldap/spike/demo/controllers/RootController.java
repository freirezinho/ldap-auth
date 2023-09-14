package br.com.ldap.spike.demo.controllers;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import br.com.ldap.spike.demo.model.LoginBody;
import br.com.ldap.spike.demo.services.UserDirectoryService;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@RestController
public class RootController {

    final UserDirectoryService adService;

    @GetMapping("/")
    public String index() {
        return "Yell-o";
    }

    @PostMapping(value = "/auth/ldap", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> authADuser(@RequestBody LoginBody body) {
        String authRes = adService.authUser(body.getUsername(), body.getPassword());
        return ResponseEntity.status(HttpStatus.OK).body(authRes);
    }

    @GetMapping("/auth/test")
    public ResponseEntity<Object> testAuth(@RequestHeader String authorization) {
        String token = authorization.split("Bearer ")[1];
        String permission = adService.getPermissionsFromToken(token);
        return ResponseEntity.status(HttpStatus.OK).body(permission);
    }

    @GetMapping("/user/{userId}")
    public String user(@PathVariable String userId) {
        return adService.getUser(userId);
    }

    @GetMapping("/user/{userId}/group")
    public String group(@PathVariable String userId) {
        return adService.getUserGroup(userId);
    }
}
