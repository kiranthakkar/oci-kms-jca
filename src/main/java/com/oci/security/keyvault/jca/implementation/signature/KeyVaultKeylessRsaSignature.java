package com.oci.security.keyvault.jca.implementation.signature;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.util.Base64;
import java.util.logging.Logger;
import static java.util.logging.Level.INFO;

/**
 * key vault Rsa signature to support key less
 */
abstract class KeyVaultKeylessRsaSignature extends AbstractKeyVaultKeylessSignature {

    private final String keyVaultDigestName;
    private static final Logger LOGGER = Logger.getLogger(KeyVaultKeylessRsaSignature.class.getName());

    /**
     * Construct a new KeyVaultKeyLessRsaSignature
     */
    KeyVaultKeylessRsaSignature(String digestName, String keyVaultDigestName) {
    	LOGGER.log(INFO,"KeyVaultKeylessRsaSignature Constructor is invoked");
    	if (digestName != null) {
            try {
                messageDigest = MessageDigest.getInstance(digestName);
            } catch (NoSuchAlgorithmException e) {
                throw new ProviderException(e);
            }
        }
        this.keyVaultDigestName = keyVaultDigestName;
    }

    @Override
    protected byte[] engineSign() {
    	LOGGER.log(INFO,"KeyVaultKeylessRsaSignature engineSign is invoked");
        byte[] mHash = getDigestValue();
        String encode = Base64.getEncoder().encodeToString(mHash);
        if (keyVaultClient != null) {
            return keyVaultClient.getSignedWithPrivateKey(this.keyVaultDigestName, encode, this.getOCIAlgorithm(), keyId);
        }
        return new byte[0];
    }

}