package com.oci.security.keyvault.jca.implementation.certificates;

import java.security.Key;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.logging.Logger;
import static java.util.logging.Level.INFO;

import com.oci.security.keyvault.jca.implementation.OCIKeyVaultClient;

/**
 * Store certificates loaded from KeyVault.
 */
public final class OCIKeyVaultCertificates implements OCICertificates {
	/**
     * Stores the list of aliases.
     */
    private List<String> aliases = new ArrayList<>();

    /**
     * Stores the certificates by alias.
     */
    private final Map<String, Certificate> certificates = new HashMap<>();

    /**
     * Stores the certificate keys by alias.
     */
    private final Map<String, Key> certificateKeys = new HashMap<>();

    private OCIKeyVaultClient keyVaultClient;
    
    private static final Logger LOGGER = Logger.getLogger(OCIKeyVaultCertificates.class.getName());

    public OCIKeyVaultCertificates(String certificateAuthorityId,String cryptoEndpoint) {
    	LOGGER.log(INFO,"OCIKeyVaultCertificates Constructor is invoked with arguments");
        updateKeyVaultClient(certificateAuthorityId, cryptoEndpoint);
    }

    public void updateKeyVaultClient(String certificateAuthorityId, String cryptoEndpoint) {
    	if(keyVaultClient==null && certificateAuthorityId!=null) {
    		keyVaultClient = new OCIKeyVaultClient(certificateAuthorityId, cryptoEndpoint);
    	}
    }

    /**
     * Get certificate aliases.
     *
     * @return certificate aliases
     */
    @Override
    public List<String> getAliases() {
    	LOGGER.log(INFO,"OCIKeyVaultCertificates getAliases is invoked");
    	if(aliases.isEmpty())
    		refreshCertificates();
        return aliases;
    }

    /**
     * Get certificates.
     *
     * @return certificates
     */
    @Override
    public Map<String, Certificate> getCertificates() {
    	LOGGER.log(INFO,"OCIKeyVaultCertificates getCertificates is invoked");
    	if(certificates.isEmpty()) {
    		refreshCertificates();
    	}
        return certificates;
    }

    @Override
    public Certificate getCertificate(String alias) {
    	return certificates.get(alias);
    }
    
    @Override
    public Key getKey(String alias) {
    	return certificateKeys.get(alias);
    }
    /**
     * Get certificates.
     *
     * @return certificate keys
     */
    @Override
    public Map<String, Key> getCertificateKeys() {
    	LOGGER.log(INFO,"OCIKeyVaultCertificates getCertificateKeys is invoked");
    	if(certificateKeys.isEmpty()) {
    		refreshCertificates();
    	}
        return certificateKeys;
    }

    /**
     * Refresh certificates. Including certificates, aliases, certificate keys.
     *
     */
    public synchronized void refreshCertificates() {
    	LOGGER.log(INFO,"OCIKeyVaultCertificates refreshCertificates is invoked");
        aliases = keyVaultClient.getAliases();
	    for(int i=0;i<aliases.size();i++) {
	    	String alias = aliases.get(i);
	        Key key = keyVaultClient.getKey(alias, null);
	        if(!Objects.isNull(key)) {
	        	certificateKeys.put(alias, key);
	        }
	        Certificate cert = keyVaultClient.getCertificate(alias);
	        if(!Objects.isNull(cert)) {
	        	certificates.put(alias, cert);
	        }
	    }
	    LOGGER.log(INFO,"OCIKeyVaultCertificates refreshCertificates is completed {0}", aliases);
    }

    /**
     * Delete certificate info by alias if exits
     *
     * @param alias deleted certificate
     */
    @Override
    public void deleteEntry(String alias) {
    	LOGGER.log(INFO,"OCIKeyVaultCertificates deleteEntry is invoked for alias {0}", alias);
        if (aliases != null) {
            aliases.remove(alias);
            certificates.remove(alias);
            certificateKeys.remove(alias);
        }
    }
}