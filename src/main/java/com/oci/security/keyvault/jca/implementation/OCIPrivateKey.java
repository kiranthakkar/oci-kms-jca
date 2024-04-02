package com.oci.security.keyvault.jca.implementation;

import java.security.PrivateKey;

import javax.crypto.SecretKey;

/**
 * KeyVault fake private which work when key less
 */
public class OCIPrivateKey implements PrivateKey, SecretKey {

    /**
     * Stores the serial version UID.
     */
    public static final long serialVersionUID = 12312;

    public static long getSerialVersionUID() {
        return serialVersionUID;
    }

    private String kid;
    private String algorithm;
    private int length;
    private String keyName;
    private transient OCIKeyVaultClient keyVaultClient;

    /**
     * Builder for key vault private key
     * @param algorithm algorithm
     * @param kid The key id
     * @param keyName
     * @param length
     * @param keyVaultClient related keyVaultClient
     */
    public OCIPrivateKey(String algorithm, String kid, String keyName,int length, OCIKeyVaultClient keyVaultClient) {
        this.algorithm = algorithm;
        this.kid = kid;
        this.keyName = keyName;
        this.length = length;
        this.keyVaultClient = keyVaultClient;
    }

    /**
     * Get related keyVaultClient, which will be used when signature
     * @return related keyVaultClient
     */
    public OCIKeyVaultClient getKeyVaultClient() {
        return keyVaultClient;
    }
    
    /**
     * Store the KeyId
     * @param client
     */
    public void setOCIKeyVaultClient(OCIKeyVaultClient client) {
        this.keyVaultClient = client;
    }

    /**
     * Get the KeyId
     * @return the KeyId
     */
    public String getKid() {
        return kid;
    }

    /**
     * Store the KeyId
     * @param kid the KeyId
     */
    public void setKid(String kid) {
        this.kid = kid;
    }

    /**
     * Store key vault certificate algorithm
     * @param algorithm algorithm
     */
    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public byte[] getEncoded() {
        return new byte[2048];
    }
    
    public void setKeyName(String keyName) {
    	this.keyName = keyName;
    }
    public String getKeyName() {
    	return this.keyName;
    }
    
    public void setKeyLenmgth(int length) {
    	this.length = length;
    }
    public int getKeyLength() {
    	return this.length;
    }
}
