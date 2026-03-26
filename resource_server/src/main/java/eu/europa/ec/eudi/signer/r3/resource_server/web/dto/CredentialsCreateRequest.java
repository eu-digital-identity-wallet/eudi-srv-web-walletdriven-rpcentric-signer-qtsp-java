/*
 Copyright 2024 European Commission

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

package eu.europa.ec.eudi.signer.r3.resource_server.web.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

public class CredentialsCreateRequest {

    /**
     * credentialCreationRequest object as defined in CSC DM.
     * certificatePolicy is Required Conditional, subjectData is Optional.
     */
    @NotNull(message = "Missing required parameter credentialCreationRequest")
    @Valid
    @JsonProperty("credentialCreationRequest")
    private CredentialCreationRequest credentialCreationRequest;

    private String clientData;

    public static class CredentialCreationRequest {
        // Required Conditional per CSC DM — may be empty string if not needed
        private String certificatePolicy;

        // Optional — subject data to include in the certificate (name, country, etc.)
        private SubjectData subjectData;

        public String getCertificatePolicy() { return certificatePolicy; }
        public void setCertificatePolicy(String certificatePolicy) { this.certificatePolicy = certificatePolicy; }

        public SubjectData getSubjectData() { return subjectData; }
        public void setSubjectData(SubjectData subjectData) { this.subjectData = subjectData; }
    }

    public static class SubjectData {
        private String givenName;
        private String surname;
        private String issuingCountry;

        public String getGivenName() { return givenName; }
        public void setGivenName(String givenName) { this.givenName = givenName; }
        public String getSurname() { return surname; }
        public void setSurname(String surname) { this.surname = surname; }
        public String getIssuingCountry() { return issuingCountry; }
        public void setIssuingCountry(String issuingCountry) { this.issuingCountry = issuingCountry; }
    }

    public CredentialCreationRequest getCredentialCreationRequest() { return credentialCreationRequest; }
    public void setCredentialCreationRequest(CredentialCreationRequest credentialCreationRequest) {
        this.credentialCreationRequest = credentialCreationRequest;
    }

    public String getClientData() { return clientData; }
    public void setClientData(String clientData) { this.clientData = clientData; }

    @Override
    public String toString() {
        return "CredentialsCreateRequest{credentialCreationRequest=" + credentialCreationRequest + ", clientData='" + clientData + "'}";
    }
}
