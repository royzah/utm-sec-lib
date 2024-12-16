import { CreateLogger } from '../utils';
import * as crypto from 'crypto';

const logs = CreateLogger();

export interface CertificateAttributes {
    certificateSigningRequest: crypto.X509Certificate;
    signerPrivateKey: crypto.KeyObject;
    parentCert?: crypto.X509Certificate;
    isCA: boolean;
    validForDays?: number;
}

export class DistinguishedName {
    constructor(
        public readonly commonName: string,
        public readonly organization: string,
        public readonly organizationUnit: string,
        public readonly country: string,
        public readonly locality: string
    ) {
        this.validateFields();
    }

    private validateFields(): void {
        const requiredFields = [
            { value: this.commonName, name: 'Common name' },
            { value: this.organization, name: 'Organization' },
            { value: this.organizationUnit, name: 'Organization unit' },
            { value: this.country, name: 'Country' },
            { value: this.locality, name: 'Locality' }
        ];

        for (const { value, name } of requiredFields) {
            if (!value?.trim()) {
                const message = `${name} cannot be empty`;
                logs.error(message);
                throw new Error(message);
            }
        }
    }
}

interface X509Subject {
    readonly CN: string;
    readonly O: string;
    readonly OU: string;
    readonly C: string;
    readonly L: string;
}

export function CreateX509Subject(distinguishedName: DistinguishedName): string {
    try {
        const subject = mapToX509Subject(distinguishedName);
        checkX509SubjectRequiredFields(subject);
        return formatX509Subject(subject);
    } catch (error) {
        const message = error instanceof Error ? error.message : 'An unknown error occurred';
        logs.error(`Failed to create X.509 subject: ${message}`);
        throw new Error(message);
    }
}

function mapToX509Subject(dn: DistinguishedName): X509Subject {
    return {
        CN: dn.commonName,
        O: dn.organization,
        OU: dn.organizationUnit,
        C: dn.country,
        L: dn.locality,
    };
}

function checkX509SubjectRequiredFields(subject: X509Subject): void {
    const requiredFields: Array<{ field: keyof X509Subject; name: string }> = [
        { field: 'CN', name: 'Common name' },
        { field: 'O', name: 'Organization' },
        { field: 'OU', name: 'Organization unit' },
        { field: 'C', name: 'Country' },
        { field: 'L', name: 'Locality' }
    ];

    for (const { field, name } of requiredFields) {
        if (!subject[field]?.trim()) {
            const message = `${name} cannot be empty`;
            logs.error(message);
            throw new Error(message);
        }
    }
}

function formatX509Subject(subject: X509Subject): string {
    const fields: Array<keyof X509Subject> = ['CN', 'OU', 'O', 'L', 'C'];
    return fields.map(field => `${field}=${subject[field]}`).join(',');
}