package com.example.sing.verify.domain.models;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.Accessors;

import java.util.Date;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Accessors(chain = true)
public class SignatureRecordModel {

    private Long id;
    private String fileName;
    private String signerCommonName;
    private Date sigingdate;
    private byte[] document;
    private byte[] signature;
    private byte[] certificate;
    private Boolean isValid;
}
