package com.mattwelke;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Post;

@Controller
public class EncryptionController {

    private EncryptionService service;

    public EncryptionController(EncryptionService encrypter) {
        this.service = encrypter;
    }
    
    @Post(value = "/encrypt", consumes = MediaType.TEXT_PLAIN, produces = MediaType.TEXT_PLAIN)
    public String encrypt(@Body String input) throws IllegalBlockSizeException, BadPaddingException {
        return service.encryptString(input);
    }

    @Post(value = "/decrypt", consumes = MediaType.TEXT_PLAIN, produces = MediaType.TEXT_PLAIN)
    public String decrypt(@Body String input) throws IllegalBlockSizeException, BadPaddingException {
        return service.decryptString(input);
    }
}
