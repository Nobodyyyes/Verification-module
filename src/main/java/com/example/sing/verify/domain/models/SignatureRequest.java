package com.example.sing.verify.domain.models;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.Accessors;

import java.time.LocalDate;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Accessors(chain = true)
public class SignatureRequest {

    private byte[] data;
    private String subjectCN;
    private String organization;
    private String country;
    private LocalDate validFrom;
    private LocalDate validTo;
    private int keySize = 2048;
}
