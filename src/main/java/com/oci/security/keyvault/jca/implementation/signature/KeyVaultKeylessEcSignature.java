package com.oci.security.keyvault.jca.implementation.signature;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.util.Base64;
import java.util.logging.Logger;
import static java.util.logging.Level.INFO;

/**
 * KeyVault EC signature to support key less
 */
abstract class KeyVaultKeylessEcSignature extends AbstractKeyVaultKeylessSignature {

    private final String keyVaultDigestName;
    private static final Logger LOGGER = Logger.getLogger(KeyVaultKeylessEcSignature.class.getName());

    /**
     * Constructs a new KeyVaultKeylessEcSignature that will use the specified digest
     */
    KeyVaultKeylessEcSignature(String digestName, String keyVaultDigestName) {
    	super();
    	LOGGER.log(INFO,"KeyVaultKeylessEcSignature Constructor is invoked");
        try {
            messageDigest = MessageDigest.getInstance(digestName);
        } catch (NoSuchAlgorithmException e) {
            throw new ProviderException(e);
        }
        this.keyVaultDigestName = keyVaultDigestName;
    }

    @Override
    protected byte[] engineSign() {
    	LOGGER.log(INFO,"KeyVaultKeylessEcSignature engineSign is invoked");
        byte[] mHash = getDigestValue();
        String encode = Base64.getEncoder().encodeToString(mHash);
        if (keyVaultClient != null) {
        	return keyVaultClient.getSignedWithPrivateKey(keyVaultDigestName, encode, this.getOCIAlgorithm(), keyId);
        }
        return new byte[0];
    }

}