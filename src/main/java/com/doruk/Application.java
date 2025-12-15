package com.doruk;

import io.micronaut.runtime.Micronaut;

public class Application {

    public static void main(String[] args) {
        Micronaut.run(Application.class, args);
    }
}

/**
 * also just asking, if there's a security or any vulnerability in this project, is it gonna hamper other projects directly ? like as its a separate project running only on localhost, and other projects are gonna rely on it. however the main feature of this project is to maintain the keys right ? so as long as the private keys aren't exposed, it's security compromises aren't gonna impact other apps much.
 *
 *
 *
 * what it does is uses, the private keys to sign jwt once other apps request it, then other apps will just ask for public keys and themself will verify, only called this app to sign new jwt right ? and it cycles the keys.
 *
 *
 *
 * or any other ways it can affect my security of other apps if it is vulnerable to any attacks ?
 *
 *
 *
 * just answer, don't modify the code files.
 */