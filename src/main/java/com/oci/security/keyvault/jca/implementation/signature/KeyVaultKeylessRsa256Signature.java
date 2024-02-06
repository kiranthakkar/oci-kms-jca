package com.oci.security.keyvault.jca.implementation.signature;

import com.oracle.bmc.keymanagement.model.SignDataDetails.SigningAlgorithm;

/**
 * key vault Rsa signature to support key less
 */
public class KeyVaultKeylessRsa256Signature extends KeyVaultKeylessRsaSignature {

    /**
     * Construct a new KeyVaultKeyLessRsaSignature
     */
    public KeyVaultKeylessRsa256Signature() {
        super("SHA-256", "RS256");
    }

    @Override
    public String getAlgorithmName() {
        return "SHA256withRSA";
    }
    
    public SigningAlgorithm getOCIAlgorithm() {
    	return SigningAlgorithm.Sha256RsaPkcs1V15; 
    }
}