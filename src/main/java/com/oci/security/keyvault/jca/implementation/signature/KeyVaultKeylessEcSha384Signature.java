package com.oci.security.keyvault.jca.implementation.signature;

import com.oracle.bmc.keymanagement.model.SignDataDetails.SigningAlgorithm;

/**
 * key vault SHA384
 */
public final class KeyVaultKeylessEcSha384Signature extends KeyVaultKeylessEcSignature {

    @Override
    public String getAlgorithmName() {
        return "SHA384withECDSA";
    }

    /**
     * support SHA-384
     */
    public KeyVaultKeylessEcSha384Signature() {
        super("SHA-384", "ES384");
    }
    
    public SigningAlgorithm getOCIAlgorithm() {
    	return SigningAlgorithm.EcdsaSha384; 
    }
}