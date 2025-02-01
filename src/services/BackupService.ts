import { BaseService } from "@/services/BaseService";
import { CommonOptions } from "@/tools/options";

export interface BackupFileInfo {
    key: string;
    size: number;
    modified: string;
}

export class BackupService extends BaseService {
    /**
     * Returns list with all available backup files.
     *
     * @throws {ClientResponseError}
     */
    getFullList(options?: CommonOptions): Array<BackupFileInfo> {
        options = Object.assign(
            {
                method: "GET",
            },
            options,
        );

        return this.client.send("/api/backups", options);
    }

    /**
     * Initializes a new backup.
     *
     * @throws {ClientResponseError}
     */
    create(basename: string, options?: CommonOptions): boolean {
        options = Object.assign(
            {
                method: "POST",
                body: {
                    name: basename,
                },
            },
            options,
        );

        this.client.send("/api/backups", options);
        return true;
    }

    /**
     * Uploads an existing backup file.
     *
     * Example:
     *
     * ```js
     * await pb.backups.upload({
     *     file: new Blob([...]),
     * });
     * ```
     *
     * @throws {ClientResponseError}
     */
    upload(
        bodyParams: { [key: string]: any } | FormData,
        options?: CommonOptions,
    ): boolean {
        options = Object.assign(
            {
                method: "POST",
                body: bodyParams,
            },
            options,
        );

        this.client.send("/api/backups/upload", options);
        return true;
    }

    /**
     * Deletes a single backup file.
     *
     * @throws {ClientResponseError}
     */
    delete(key: string, options?: CommonOptions): boolean {
        options = Object.assign(
            {
                method: "DELETE",
            },
            options,
        );

        this.client.send(`/api/backups/${encodeURIComponent(key)}`, options);
        return true;
    }

    /**
     * Initializes an app data restore from an existing backup.
     *
     * @throws {ClientResponseError}
     */
    restore(key: string, options?: CommonOptions): boolean {
        options = Object.assign(
            {
                method: "POST",
            },
            options,
        );

        this.client.send(`/api/backups/${encodeURIComponent(key)}/restore`, options);
        return true;
    }

    /**
     * Builds a download url for a single existing backup using a
     * superuser file token and the backup file key.
     *
     * The file token can be generated via `pb.files.getToken()`.
     */
    getDownloadURL(token: string, key: string): string {
        return this.client.buildURL(
            `/api/backups/${encodeURIComponent(key)}?token=${encodeURIComponent(token)}`,
        );
    }
}
