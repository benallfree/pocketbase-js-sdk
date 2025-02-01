import { BaseService } from "@/services/BaseService";
import { CommonOptions } from "@/tools/options";

interface appleClientSecret {
    secret: string;
}

export class SettingsService extends BaseService {
    /**
     * Fetch all available app settings.
     *
     * @throws {ClientResponseError}
     */
    getAll(options?: CommonOptions): { [key: string]: any } {
        options = Object.assign(
            {
                method: "GET",
            },
            options,
        );

        return this.client.send("/api/settings", options);
    }

    /**
     * Bulk updates app settings.
     *
     * @throws {ClientResponseError}
     */
    update(
        bodyParams?: { [key: string]: any } | FormData,
        options?: CommonOptions,
    ): { [key: string]: any } {
        options = Object.assign(
            {
                method: "PATCH",
                body: bodyParams,
            },
            options,
        );

        return this.client.send("/api/settings", options);
    }

    /**
     * Performs a S3 filesystem connection test.
     *
     * The currently supported `filesystem` are "storage" and "backups".
     *
     * @throws {ClientResponseError}
     */
    testS3(filesystem: string = "storage", options?: CommonOptions): boolean {
        options = Object.assign(
            {
                method: "POST",
                body: {
                    filesystem: filesystem,
                },
            },
            options,
        );

        this.client.send("/api/settings/test/s3", options);
        return true;
    }

    /**
     * Sends a test email.
     *
     * The possible `emailTemplate` values are:
     * - verification
     * - password-reset
     * - email-change
     *
     * @throws {ClientResponseError}
     */
    testEmail(
        collectionIdOrName: string,
        toEmail: string,
        emailTemplate: string,
        options?: CommonOptions,
    ): boolean {
        options = Object.assign(
            {
                method: "POST",
                body: {
                    email: toEmail,
                    template: emailTemplate,
                    collection: collectionIdOrName,
                },
            },
            options,
        );

        this.client.send("/api/settings/test/email", options);
        return true;
    }

    /**
     * Generates a new Apple OAuth2 client secret.
     *
     * @throws {ClientResponseError}
     */
    generateAppleClientSecret(
        clientId: string,
        teamId: string,
        keyId: string,
        privateKey: string,
        duration: number,
        options?: CommonOptions,
    ): appleClientSecret {
        options = Object.assign(
            {
                method: "POST",
                body: {
                    clientId,
                    teamId,
                    keyId,
                    privateKey,
                    duration,
                },
            },
            options,
        );

        return this.client.send("/api/settings/apple/generate-client-secret", options);
    }
}
