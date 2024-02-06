package com.oci.security.keyvault.jca;

import java.security.KeyStore;


public final class KeyVaultLoadStoreParameter implements KeyStore.LoadStoreParameter {

    private final String certAuthorityId;
    private final String cryptoEndpoint;
    
    
    public KeyVaultLoadStoreParameter(String certAuthorityId, String cryptoEndpoint) {
        this.certAuthorityId = certAuthorityId;
        this.cryptoEndpoint = cryptoEndpoint;
    }

    @Override
    public KeyStore.ProtectionParameter getProtectionParameter() {
        return null;
    }


    public String getCertAuthorityId() {
        return certAuthorityId;
    }
    
    public String getCryptoEndpoint() { 
    	return cryptoEndpoint;
    }
}
