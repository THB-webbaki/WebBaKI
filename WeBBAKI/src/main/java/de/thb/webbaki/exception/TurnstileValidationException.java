package de.thb.webbaki.exception;

import org.springframework.security.core.AuthenticationException;

public class TurnstileValidationException extends AuthenticationException {
    public TurnstileValidationException(String msg) { super(msg); }
}