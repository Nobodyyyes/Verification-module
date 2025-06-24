package com.example.sing.verify.domain.entities;

import jakarta.persistence.*;
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
@Entity
@Table(name = "SIGNATURE_RECORD")
public class SignatureRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "SIGNATURE_RECORD_SEQ")
    @SequenceGenerator(name = "SIGNATURE_RECORD_SEQ", sequenceName = "SIGNATURE_RECORD_SEQ", allocationSize = 1)
    private Long id;

    @Column(name = "FILE_NAME")
    private String fileName;

    @Column(name = "SIGNER_COMMON_NAME")
    private String signerCommonName;

    @Column(name = "SIGNING_DATE")
    private Date sigingdate;

    @Column(name = "DOCUMENT")
    @Lob
    private byte[] document;

    @Column(name = "SIGNATURE")
    @Lob
    private byte[] signature;

    @Column(name = "CERTIFICATE")
    @Lob
    private byte[] certificate;

    @Column(name = "IS_VALID")
    private Boolean isValid;
}
