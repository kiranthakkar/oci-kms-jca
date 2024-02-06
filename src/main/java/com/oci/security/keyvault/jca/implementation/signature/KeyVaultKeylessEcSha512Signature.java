package com.oci.security.keyvault.jca.implementation.signature;

import com.oracle.bmc.keymanagement.model.SignDataDetails.SigningAlgorithm;

/**
 * key vault SHA512
 */
public final class KeyVaultKeylessEcSha512Signature extends KeyVaultKeylessEcSignature {

    @Override
    public String getAlgorithmName() {
        return "SHA512withECDSA";
    }

    /**
     * support SHA-512
     */
    public KeyVaultKeylessEcSha512Signature() {
        super("SHA-512", "ES512");
    }
    
    public SigningAlgorithm getOCIAlgorithm() {
    	return SigningAlgorithm.EcdsaSha512; 
    }

}