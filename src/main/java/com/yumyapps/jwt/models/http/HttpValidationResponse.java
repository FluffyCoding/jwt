package com.yumyapps.jwt.models.http;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.http.HttpStatus;

import java.util.Date;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
public class HttpValidationResponse {

    private Date timeStamp;
    private int httpStatusCode;
    private HttpStatus httpStatus;
    private String reason;
    private String message;

    private List<ValidatorResponseMessage> validations;


    public HttpValidationResponse(int httpStatusCode, HttpStatus httpStatus, String reason, String message, List<ValidatorResponseMessage> validations) {
        this.timeStamp = new Date();
        this.httpStatusCode = httpStatusCode;
        this.httpStatus = httpStatus;
        this.reason = reason;
        this.message = message;
        this.validations = validations;
    }
}
