package com.doruk.dto;

import com.nimbusds.jose.jwk.ECKey;

public record ActiveKeys(ECKey primary, ECKey secondary) {}

