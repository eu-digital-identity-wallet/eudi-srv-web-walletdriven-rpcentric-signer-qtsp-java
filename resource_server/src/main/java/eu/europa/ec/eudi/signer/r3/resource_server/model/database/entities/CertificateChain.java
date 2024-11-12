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

package eu.europa.ec.eudi.signer.r3.resource_server.model.database.entities;

import jakarta.persistence.*;

@Entity
@Table(name="certificate_chain")
public class CertificateChain {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 2000)
    private String certificate;

    @ManyToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "credentials_id", nullable = false)
    private Credentials credential;

    public CertificateChain() {
    }

    public CertificateChain(long id, String certificate) {
        this.id = id;
        this.certificate = certificate;
    }

    public String getCertificate() {
        return this.certificate;
    }

    public void setCertificate(String certificate) {
        this.certificate = certificate;
    }

    public Credentials getCredential() {
        return this.credential;
    }

    public void setCredential(Credentials credential) {
        this.credential = credential;
    }
}
