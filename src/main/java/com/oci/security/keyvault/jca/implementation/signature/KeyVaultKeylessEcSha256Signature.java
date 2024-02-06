package com.oci.security.keyvault.jca.implementation.signature;

import com.oracle.bmc.keymanagement.model.SignDataDetails.SigningAlgorithm;

/**
 * key vault SHA256
 */
public final class KeyVaultKeylessEcSha256Signature extends KeyVaultKeylessEcSignature {

    @Override
    public String getAlgorithmName() {
        return "SHA256withECDSA";
    }

    /**
     * support SHA-256
     */
    public KeyVaultKeylessEcSha256Signature() {
        super("SHA-256", "ES256");
    }

    public SigningAlgorithm getOCIAlgorithm() {
    	return SigningAlgorithm.EcdsaSha256; 
    }

}