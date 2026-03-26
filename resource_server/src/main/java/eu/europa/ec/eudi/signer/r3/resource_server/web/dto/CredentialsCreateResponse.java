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

public class CredentialsCreateResponse {

    private String credentialID;

    public CredentialsCreateResponse() {}

    public CredentialsCreateResponse(String credentialID) {
        this.credentialID = credentialID;
    }

    public String getCredentialID() { return credentialID; }
    public void setCredentialID(String credentialID) { this.credentialID = credentialID; }

    @Override
    public String toString() {
        return "CredentialsCreateResponse{credentialID='" + credentialID + "'}";
    }
}
