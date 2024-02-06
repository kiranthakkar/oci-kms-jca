package com.oci.security.keyvault.jca.implementation.signature;

import com.oracle.bmc.keymanagement.model.SignDataDetails.SigningAlgorithm;

/**
 * key vault Rsa signature to support key less
 */
public class KeyVaultKeylessRsa512Signature extends KeyVaultKeylessRsaSignature {

    /**
     * Construct a new KeyVaultKeyLessRsaSignature
     */
    public KeyVaultKeylessRsa512Signature() {
        super("SHA-512", "RS512");
    }

    @Override
    public String getAlgorithmName() {
        return "SHA512withRSA";
    }
    
    public SigningAlgorithm getOCIAlgorithm() {
    	return SigningAlgorithm.Sha512RsaPkcs1V15; 
    }
}