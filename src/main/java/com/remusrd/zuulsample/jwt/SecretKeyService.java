package com.remusrd.zuulsample.jwt;

import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

@Component
@ConditionalOnProperty("security.jwt.key.public")
public class SecretKeyService {

	@Value("${security.jwt.key.public}")
	private String publicKey;


	public RSAPublicKey getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] publicBytes = Base64.decodeBase64(publicKey);
		KeySpec keySpec = new X509EncodedKeySpec(publicBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return (RSAPublicKey) keyFactory.generatePublic(keySpec);
	}

}