package com.example.sing.verify.domain.models;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.Accessors;

import java.util.Date;
import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Accessors(chain = true)
public class CertificateInfo {

    private String subject;
    private String issuer;
    private Date validFrom;
    private Date validTo;
    private String serialNumber;
    private String signatureAlgorithm;
    private String publicKeyAlgorithm;
    private List<String> keyUsage;
    private List<String> extendedKeyUsage;
    private int version;
    private List<String> subjectAlternativeNames;
}
