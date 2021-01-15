package juhwan.study.jwt.controller;

import juhwan.study.jwt.config.jwt.JwtFilter;
import juhwan.study.jwt.config.jwt.TokenProvider;
import juhwan.study.jwt.dto.LoginDto;
import juhwan.study.jwt.dto.TokenDto;
import lombok.RequiredArgsConstructor;
import lombok.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class AuthController {

    private final TokenProvider tokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    @PostMapping("/authenticate")
    public ResponseEntity<TokenDto> authorize(@Valid @RequestBody LoginDto loginDto){
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

        Authentication authenticate = authenticationManagerBuilder
                .getObject()
                .authenticate(authenticationToken);

        SecurityContextHolder
                .getContext()
                .setAuthentication(authenticate);

        String jwt = tokenProvider.createToken(authenticate);

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(JwtFilter.AUTHORIZATION_HEADER,"Bearer "+ jwt);
        return new ResponseEntity<>(new TokenDto(jwt),httpHeaders, HttpStatus.OK);

    }

}
