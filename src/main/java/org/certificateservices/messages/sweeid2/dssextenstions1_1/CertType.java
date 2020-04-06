package org.certificateservices.messages.sweeid2.dssextenstions1_1;

/**
 * Enumeration of available values to CertRequestPropertiesType CertType
 * Created by philip on 11/01/17.
 */
public enum CertType {
    PKC("PKC"),
    QC("QC"),
    QC_SSD("QC/SSCD");

    private String value;
    CertType(String value){
        this.value = value;
    }

    public String getValue(){
        return value;
    }
}
